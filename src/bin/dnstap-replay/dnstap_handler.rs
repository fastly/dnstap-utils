// Copyright 2021-2022 Fastly, Inc.

use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use ip_network_table::IpNetworkTable;
use log::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use dnstap_utils::dnstap;
use dnstap_utils::util::dns_message_is_truncated;
use dnstap_utils::util::try_from_u8_slice_for_ipaddr;
use dnstap_utils::util::DnstapHandlerError;

use crate::{Channels, Opts};

/// Duration for [`DnstapHandler`]'s to wait for a response from the DNS server under test.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Maximum UDP response message size that can be received from the DNS server under test.
const DNS_RESPONSE_BUFFER_SIZE: usize = 4096;

/// Process the dnstap protobuf payloads and re-send them to the DNS server under test.
///
/// Decoded protobuf payloads are received over a channel from a [`crate::FrameHandler`]. The
/// original address of the DNS client that sent the DNS query is used to construct a PROXY v2
/// header which is prepended to the DNS query which is sent to the DNS server specified in the
/// configuration.  The response that the DNS server sends is then compared to the original DNS
/// response message included in the dnstap payload and logged if they differ.
///
/// This requires two specializations from the DNS server that we receive dnstap logging data and
/// the DNS server that we re-send DNS queries to:
///
/// 1. The DNS server that sends the dnstap payloads needs to produce `AUTH_RESPONSE` messages that
///    include both the `query_message` and `response_message` fields. It is optional to fill out
///    both of these fields, and DNS servers typically only fill out the `response_message` field
///    for `AUTH_RESPONSE` dnstap payloads.
/// 2. The DNS server under test needs to understand the PROXY v2 header which the
///    [`DnstapHandler`] prepends to the DNS query. An unmodified DNS server will not recognize the
///    prepended DNS queries that the [`DnstapHandler`] sends and will likely respond with the DNS
///    `FORMERR` or `NOTIMP` RCODEs.
pub struct DnstapHandler {
    /// Server options.
    opts: Opts,

    /// Server channels.
    channels: Channels,

    /// Networks to ignore queries from.
    ignore_query_nets: Option<IpNetworkTable<bool>>,

    /// The result of the status monitor check. Controls whether mismatches should be emitted into
    /// the errors channel (if true) or suppressed (if false).
    match_status: Arc<AtomicBool>,

    /// Per-handler DNS client socket to use to send DNS queries to the DNS server under test. This
    /// is an [`Option<UdpSocket>`] rather than a [`UdpSocket`] because in the case of a timeout
    /// the socket will need to be closed and reopened.
    socket: Option<UdpSocket>,

    /// Buffer to received UDP response messages from the DNS server under test.
    recv_buf: [u8; DNS_RESPONSE_BUFFER_SIZE],
}

#[derive(Error, Debug)]
enum DnstapHandlerInternalError {
    #[error("Non-UDP dnstap payload was discarded")]
    DiscardNonUdp,
}

impl DnstapHandler {
    /// Create a new [`DnstapHandler`] that receives decoded dnstap protobuf payloads from the
    /// `channel_receiver` channel, synthesizes new DNS client queries from the received dnstap
    /// payloads, and sends them to the DNS server under test.
    ///
    /// Server options are specified in `opts`, such as:
    ///
    /// * `opts.dns`: The DNS server address/port to send DNS queries to.
    /// * `opts.dscp`: The DSCP value to use for re-sent DNS queries.
    /// * `opts.proxy`: Whether to add PROXY v2 header to re-sent DNS queries.
    /// * `opts.ignore_tc`: Whether to ignore UDP responses with the TC bit set.
    ///
    /// The `match_status` variable is a shared flag used to suppress mismatches. It needs to be
    /// externally set to `true` to enable the generation of mismatch output and metrics.
    ///
    /// Responses received from the DNS server under test that don't match the original response in
    /// the dnstap payload will be sent via the channel `channel_error_sender` if `match_status` is
    /// `true`.
    ///
    /// If a DNS timeout occurs when re-querying the DNS server under test, the dnstap payload will
    /// be sent via the channel `channel_timeout_sender`.
    pub async fn new(
        opts: &Opts,
        channels: &Channels,
        match_status: Arc<AtomicBool>,
    ) -> Result<Self> {
        // Create the IpNetworkTable of networks to ignore queries from.
        let ignore_query_nets = if !opts.ignore_query_net.is_empty() {
            let mut table = IpNetworkTable::new();
            for net in &opts.ignore_query_net {
                table.insert(*net, true);
            }
            Some(table)
        } else {
            None
        };

        let mut handler = DnstapHandler {
            opts: opts.clone(),
            channels: channels.clone(),
            ignore_query_nets,
            match_status,
            socket: None,
            recv_buf: [0; DNS_RESPONSE_BUFFER_SIZE],
        };

        // Setup the private UDP client socket for this handler.
        handler.maybe_setup_socket().await?;

        Ok(handler)
    }

    /// Create, bind, and connect the UDP client socket if needed.
    async fn maybe_setup_socket(&mut self) -> Result<()> {
        if self.socket.is_none() {
            // Determine whether to create an IPv4 or IPv6 client socket.
            let local_address: SocketAddr = if self.opts.dns.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?;

            // Bind the socket.
            let socket = UdpSocket::bind(local_address).await?;

            // Set the DSCP value.
            if let Some(dscp) = self.opts.dscp {
                set_udp_dscp(&socket, dscp)?;
            }

            // Connect the socket to the DNS server under test.
            socket.connect(&self.opts.dns).await?;

            debug!("Connected socket to DNS server: {:?}", &socket);

            // Store the socket for use by the main processing loop.
            self.socket = Some(socket);
        }
        Ok(())
    }

    /// Close and reopen the UDP client socket.
    async fn restart_socket(&mut self) -> Result<()> {
        // Drop the old socket.
        self.socket = None;

        // Setup the private UDP client socket for this handler again.
        self.maybe_setup_socket().await?;

        Ok(())
    }

    /// Receive dnstap protobuf payloads from a [`crate::FrameHandler`] and perform further
    /// processing.
    pub async fn run(&mut self) -> Result<()> {
        while let Ok(d) = self.channels.receiver.recv().await {
            // Check if the UDP client socket needs to be re-created.
            self.maybe_setup_socket().await?;

            // Actually process the dnstap payload.
            self.process_dnstap(d).await?
        }
        Ok(())
    }

    /// Process the outer dnstap container and if it contains a dnstap "Message" object of type
    /// `AUTH_RESPONSE`, perform further processing on it.
    async fn process_dnstap(&mut self, mut d: dnstap::Dnstap) -> Result<()> {
        // Currently only "Message" objects are defined.
        if dnstap::dnstap::Type::from_i32(d.r#type) != Some(dnstap::dnstap::Type::Message) {
            return Ok(());
        }

        let msg = match &d.message {
            Some(msg) => msg,
            None => return Ok(()),
        };

        // Check if this is an `AUTH_RESPONSE` type dnstap "Message" object.
        if dnstap::message::Type::from_i32(msg.r#type) != Some(dnstap::message::Type::AuthResponse)
        {
            return Ok(());
        }

        // Perform further processing on this message. On timeout, log the error and close and
        // reopen the UDP client socket.
        match self.process_dnstap_message(msg).await {
            Ok(_) => {
                crate::metrics::DNSTAP_PAYLOADS.success.inc();
            }
            Err(e) => {
                crate::metrics::DNSTAP_PAYLOADS.error.inc();

                if let Some(e) = e.downcast_ref::<DnstapHandlerError>() {
                    // Serialize the [`DnstapHandlerError`] instance and export it via the dnstap
                    // object's `extra` field.
                    d.extra = Some(e.serialize().to_vec());

                    match e {
                        DnstapHandlerError::Mismatch(_, _, _) => {
                            // Send to the errors channel.
                            self.send_error(d);

                            crate::metrics::DNS_COMPARISONS.mismatched.inc();
                        }

                        DnstapHandlerError::Timeout => {
                            // Send to the timeouts channel.
                            self.send_timeout(d);

                            crate::metrics::DNS_QUERIES.timeout.inc();

                            // In the case of a DNS query timeout, we can't tell the difference
                            // between a message that has genuinely been lost and one that might
                            // still be processed by the DNS server under test and returned to us
                            // on a subsequent socket read. If the latter happens, the lockstep
                            // synchronization between a sent DNS query and a received DNS response
                            // will be lost and every subsequent comparison between originally
                            // logged response message and corresponding response message received
                            // from the DNS server under test will fail because the wrong messages
                            // are being compared.
                            //
                            // This kind of failure mode could be worked around by implementing a
                            // state table for the outbound DNS queries sent to the DNS server
                            // under test but this requires parsing some portions of the DNS header
                            // and the question section as well as garbage collection of the state
                            // table to avoid filling it with timed out queries. The easier thing
                            // to do is to close the socket and open a new one.
                            self.restart_socket().await?;
                        }

                        DnstapHandlerError::MissingField => {
                            // Send to the errors channel.
                            self.send_error(d);

                            // Metric increment already handled above.
                        }
                    }
                } else if let Some(e) = e.downcast_ref::<DnstapHandlerInternalError>() {
                    match e {
                        DnstapHandlerInternalError::DiscardNonUdp => {
                            crate::metrics::DNSTAP_HANDLER_INTERNAL_ERRORS
                                .discard_non_udp
                                .inc();
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a dnstap "Message" object.
    async fn process_dnstap_message(&mut self, msg: &dnstap::Message) -> Result<()> {
        // Check if we have a connected UDP socket to send DNS queries to.
        let socket = match &self.socket {
            Some(socket) => socket,
            None => {
                bail!("No connected socket to send DNS queries");
            }
        };

        // Check if the original DNS query message was sent over UDP. If not, when the query is
        // re-sent over UDP it may elicit different behavior compared to the original transport.
        match &msg.socket_protocol {
            Some(socket_protocol) => {
                if dnstap::SocketProtocol::from_i32(*socket_protocol)
                    != Some(dnstap::SocketProtocol::Udp)
                {
                    bail!(DnstapHandlerInternalError::DiscardNonUdp);
                }
            }
            None => bail!(DnstapHandlerError::MissingField),
        };

        // Extract the `query_message` field. This is the original DNS query message sent to the
        // DNS server that logged the dnstap message.
        let query_message = match &msg.query_message {
            Some(msg) => msg,
            None => return Ok(()),
        };

        // Extract the `response_message` field. This is the original DNS response message sent by
        // the DNS server that logged the dnstap message to the original client.
        let response_message = match &msg.response_message {
            Some(msg) => msg,
            None => return Ok(()),
        };

        // Create a buffer for containing the original DNS client message, optionally with a PROXY
        // v2 header prepended. The PROXY v2 payload that we generate will be small (<100 bytes)
        // and DNS query messages are restricted by the protocol to a maximum size of 512 bytes.
        let mut buf = BytesMut::with_capacity(1024);

        // Add the PROXY v2 payload, if the dnstap handler has been configured to do so.
        if self.opts.proxy {
            add_proxy_payload(&mut buf, msg)?;
        }

        // Add the original DNS query message.
        buf.put_slice(query_message);

        // Freeze the buffer since it no longer needs to be mutated.
        let buf = buf.freeze();

        // Send the constructed query message to the DNS server under test.
        trace!("Sending DNS query: {}", hex::encode(&buf));
        socket.send(&buf).await?;

        // Receive the DNS response message from the DNS server under test, or wait for the DNS
        // query timeout to expire.
        match timeout(DNS_QUERY_TIMEOUT, socket.recv(&mut self.recv_buf)).await {
            Ok(res) => match res {
                Ok(n_bytes) => {
                    // A DNS response message was successfully received.
                    crate::metrics::DNS_QUERIES.success.inc();

                    let received_message = &self.recv_buf[..n_bytes];
                    trace!("Received DNS response: {}", hex::encode(received_message));

                    // Check if matching is enabled.
                    if self.match_status.load(Ordering::Relaxed) {
                        // Check if the DNS response message received from the DNS server under test is
                        // identical to the original DNS response message recorded in the dnstap
                        // message.
                        if response_message == received_message {
                            // Match.
                            crate::metrics::DNS_COMPARISONS.matched.inc();
                        } else if self.opts.ignore_tc
                            && (dns_message_is_truncated(response_message)
                                || dns_message_is_truncated(received_message))
                        {
                            // Either the original DNS response message or the DNS response message
                            // received from the DNS server under test was truncated, and the
                            // option to ignore TC=1 responses was enabled.
                            crate::metrics::DNS_COMPARISONS.udp_tc_ignored.inc();
                        } else {
                            // Mismatch.
                            bail!(DnstapHandlerError::Mismatch(
                                Bytes::copy_from_slice(received_message),
                                hex::encode(received_message),
                                hex::encode(response_message),
                            ));
                        }
                    } else {
                        crate::metrics::DNS_COMPARISONS.suppressed.inc();
                    }
                }
                Err(e) => {
                    crate::metrics::DNS_QUERIES.error.inc();
                    bail!(e);
                }
            },
            Err(_) => {
                bail!(DnstapHandlerError::Timeout);
            }
        }

        Ok(())
    }

    fn send_error(&self, d: dnstap::Dnstap) {
        match self.channels.error_sender.try_send(d) {
            Ok(_) => {
                crate::metrics::CHANNEL_ERROR_TX.success.inc();
            }
            Err(_) => {
                crate::metrics::CHANNEL_ERROR_TX.error.inc();
            }
        }
    }

    fn send_timeout(&self, d: dnstap::Dnstap) {
        match self.channels.timeout_sender.try_send(d) {
            Ok(_) => {
                crate::metrics::CHANNEL_TIMEOUT_TX.success.inc();
            }
            Err(_) => {
                crate::metrics::CHANNEL_TIMEOUT_TX.error.inc();
            }
        }
    }
}

fn add_proxy_payload(buf: &mut BytesMut, msg: &dnstap::Message) -> Result<()> {
    // Extract the `query_address` field and convert it to an [`IpAddr`]. This is the IP
    // address of the original client that sent the DNS query to the DNS server that logged the
    // dnstap message.
    let query_address = match &msg.query_address {
        Some(addr) => try_from_u8_slice_for_ipaddr(addr)?,
        None => bail!(DnstapHandlerError::MissingField),
    };

    // Extract the `query_port` field.
    let query_port = match &msg.query_port {
        Some(port) => *port as u16,
        None => bail!(DnstapHandlerError::MissingField),
    };

    // Add the PROXY v2 signature.
    buf.put(&b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"[..]);

    // Add the PROXY version (2) and command (1), PROXY.
    buf.put_u8(0x21);

    // Add the PROXY v2 address block.
    match query_address {
        IpAddr::V4(addr) => {
            // UDP-over-IPv4: protocol constant 0x12.
            buf.put_u8(0x12);

            // Size of the UDP-over-IPv4 address block: 12 bytes. There are two IPv4 addresses
            // (4 bytes each) and two UDP port numbers (2 bytes each).
            buf.put_u16(12);

            // Original IPv4 source address.
            buf.put_slice(&addr.octets());

            // Original IPv4 destination address. Use 0.0.0.0 since it doesn't matter and the
            // dnstap message payload may not have it.
            buf.put_u32(0);
        }
        IpAddr::V6(addr) => {
            // UDP-over-IPv6: protocol constant 0x22.
            buf.put_u8(0x22);

            // Size of the UDP-over-IPv6 address block: 36 bytes. There are two IPv6 addresses
            // (16 bytes each) and two UDP port numbers (2 bytes each).
            buf.put_u16(36);

            // Original IPv6 source address.
            buf.put_slice(&addr.octets());

            // Original IPv6 destination address. Use :: since it doesn't matter and the dnstap
            // message payload may not have it.
            buf.put_u128(0);
        }
    };

    // Original UDP source port.
    buf.put_u16(query_port);

    // Original UDP destination port. Use 53 since it doesn't matter and the dnstap message
    // payload may not have it.
    buf.put_u16(53);

    Ok(())
}

/// Utility function that sets the DSCP value on a UDP socket.
#[cfg(unix)]
fn set_udp_dscp(s: &UdpSocket, dscp: u8) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let raw_fd = s.as_raw_fd();
    let optval: libc::c_int = (dscp << 2).into();

    let ret = match s.local_addr()? {
        SocketAddr::V4(_) => unsafe {
            libc::setsockopt(
                raw_fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            )
        },
        SocketAddr::V6(_) => unsafe {
            libc::setsockopt(
                raw_fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            )
        },
    };

    match ret {
        0 => Ok(()),
        _ => bail!(
            "Failed to set DSCP value {} on socket fd {}: {}",
            dscp,
            raw_fd,
            std::io::Error::last_os_error()
        ),
    }
}

#[cfg(not(unix))]
fn set_udp_dscp(_s: &UdpSocket, _dscp: u8) -> Result<()> {
    bail!("Cannot set DSCP values on this platform");
}
