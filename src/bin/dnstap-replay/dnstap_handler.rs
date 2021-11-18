// Copyright 2021 Fastly, Inc.

use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use log::*;
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::dnstap;

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
    /// The receive side of the async channel used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`crate::FrameHandler`]'s.
    channel_receiver: async_channel::Receiver<dnstap::Dnstap>,

    /// The send side of the async channel, used by [`DnstapHandler`]'s to send error dnstap
    /// protobuf messages to the [`crate::HttpHandler`].
    channel_error_sender: async_channel::Sender<dnstap::Dnstap>,

    /// Socket address/port of the DNS server to send DNS queries to.
    dns_address: SocketAddr,

    /// Whether to add PROXY v2 header to re-sent DNS queries.
    proxy: bool,

    /// The DSCP value to use for re-sent DNS queries.
    dscp: Option<u8>,

    /// Per-handler DNS client socket to use to send DNS queries to the DNS server under test. This
    /// is an [`Option<UdpSocket>`] rather than a [`UdpSocket`] because in the case of a timeout
    /// the socket will need to be closed and reopened.
    socket: Option<UdpSocket>,

    /// Buffer to received UDP response messages from the DNS server under test.
    recv_buf: [u8; DNS_RESPONSE_BUFFER_SIZE],
}

#[derive(Error, Debug)]
enum DnstapHandlerError {
    #[error("Mismatch between logged dnstap response and re-queried DNS response, expecting {1} but received {2}")]
    Mismatch(Bytes, String, String),

    #[error("Timeout sending DNS query")]
    Timeout,

    #[error("dnstap payload is missing a required field")]
    MissingField,
}

#[derive(Error, Debug)]
enum DnstapHandlerInternalError {
    #[error("Non-UDP dnstap payload was discarded")]
    DiscardNonUdp,
}

impl DnstapHandlerError {
    pub fn serialize(&self) -> Bytes {
        let prefix = b"dnstap-replay/DnstapHandlerError\x00";
        match self {
            DnstapHandlerError::Mismatch(mismatch, _, _) => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4 + mismatch.len());
                b.extend_from_slice(prefix);
                b.put_u32(1);
                b.extend_from_slice(mismatch);
                b
            }
            DnstapHandlerError::Timeout => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4);
                b.extend_from_slice(prefix);
                b.put_u32(2);
                b
            }
            DnstapHandlerError::MissingField => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4);
                b.extend_from_slice(prefix);
                b.put_u32(3);
                b
            }
        }
        .freeze()
    }
}

impl DnstapHandler {
    /// Create a new [`DnstapHandler`] that receives decoded dnstap protobuf payloads from
    /// `channel_receiver`, synthesizes new DNS client queries and sends them to the DNS server
    /// under test specified by the address/port in `dns_address`. Responses received from the DNS
    /// server under test that don't match the original response in the dnstap payload will be sent
    /// using `channel_error_sender`.
    pub async fn new(
        channel_receiver: async_channel::Receiver<dnstap::Dnstap>,
        channel_error_sender: async_channel::Sender<dnstap::Dnstap>,
        dns_address: SocketAddr,
        proxy: bool,
        dscp: Option<u8>,
    ) -> Result<Self> {
        let mut handler = DnstapHandler {
            channel_receiver,
            channel_error_sender,
            dns_address,
            proxy,
            dscp,
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
            let local_address: SocketAddr = if self.dns_address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?;

            // Bind the socket.
            let socket = UdpSocket::bind(local_address).await?;

            // Set the DSCP value.
            if let Some(dscp) = self.dscp {
                set_udp_dscp(&socket, dscp)?;
            }

            // Connect the socket to the DNS server under test.
            socket.connect(&self.dns_address).await?;

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
        while let Ok(d) = self.channel_receiver.recv().await {
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
                crate::metrics::DNSTAP_PAYLOADS
                    .with_label_values(&["success"])
                    .inc();
            }
            Err(e) => {
                crate::metrics::DNSTAP_PAYLOADS
                    .with_label_values(&["error"])
                    .inc();

                if let Some(e) = e.downcast_ref::<DnstapHandlerError>() {
                    // Serialize the [`DnstapHandlerError`] instance and export it via the dnstap
                    // object's `extra` field.
                    d.extra = Some(e.serialize().to_vec());

                    // Send the dnstap message to the errors channel so that it can be retrieved
                    // from the /errors HTTP endpoint.
                    self.send_error(d);

                    match e {
                        DnstapHandlerError::Mismatch(_, _, _) => {
                            crate::metrics::DNS_COMPARISONS
                                .with_label_values(&["mismatch"])
                                .inc();
                        }

                        DnstapHandlerError::Timeout => {
                            crate::metrics::DNS_QUERIES
                                .with_label_values(&["timeout"])
                                .inc();

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
                            // Already handled by metric increment above.
                        }
                    }
                } else if let Some(e) = e.downcast_ref::<DnstapHandlerInternalError>() {
                    match e {
                        DnstapHandlerInternalError::DiscardNonUdp => {
                            crate::metrics::DNSTAP_HANDLER_INTERNAL_ERRORS
                                .with_label_values(&["discard_non_udp"])
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
        if self.proxy {
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
                    crate::metrics::DNS_QUERIES
                        .with_label_values(&["success"])
                        .inc();

                    let received_message = &self.recv_buf[..n_bytes];
                    trace!("Received DNS response: {}", hex::encode(received_message));

                    // Check if the DNS response message received from the DNS server under test is
                    // identical to the original DNS response message recorded in the dnstap
                    // message.
                    if response_message == received_message {
                        // Match.
                        crate::metrics::DNS_COMPARISONS
                            .with_label_values(&["match"])
                            .inc();
                    } else {
                        // Mismatch.
                        bail!(DnstapHandlerError::Mismatch(
                            Bytes::copy_from_slice(received_message),
                            hex::encode(received_message),
                            hex::encode(response_message),
                        ));
                    }
                }
                Err(e) => {
                    crate::metrics::DNS_QUERIES
                        .with_label_values(&["error"])
                        .inc();
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
        match self.channel_error_sender.try_send(d) {
            Ok(_) => {
                crate::metrics::CHANNEL_ERROR_TX
                    .with_label_values(&["success"])
                    .inc();
            }
            Err(_) => {
                crate::metrics::CHANNEL_ERROR_TX
                    .with_label_values(&["error"])
                    .inc();
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

/// Utility function that converts a slice of bytes into an [`IpAddr`]. Slices of length 4 are
/// converted to IPv4 addresses and slices of length 16 are converted to IPv6 addresses. All other
/// slice lengths are invalid. This is how IP addresses are encoded in dnstap protobuf messages.
fn try_from_u8_slice_for_ipaddr(value: &[u8]) -> Result<IpAddr> {
    match value.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(value)?)),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(value)?)),
        _ => bail!(
            "Cannot decode an IP address from a {} byte field",
            value.len()
        ),
    }
}

/// Utility function that sets the DSCP value on a UDP socket.
#[cfg(unix)]
fn set_udp_dscp(s: &UdpSocket, dscp: u8) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let raw_fd = s.as_raw_fd();
    let optval: libc::c_int = dscp.into();

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
