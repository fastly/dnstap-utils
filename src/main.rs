// Copyright 2021 Fastly, Inc.

use async_channel::bounded;
use bytes::{BufMut, BytesMut};
use clap::{value_t, App, Arg};
use extfmt::Hexlify;
use futures::SinkExt;
use log::*;
use prost::Message;
use simple_error::bail;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use tokio::net::{UdpSocket, UnixListener, UnixStream};
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

/// The codec for handshaking and decoding the "Frame Streams" protocol used by dnstap.
mod framestreams_codec;
use framestreams_codec::{Frame, FrameStreamsCodec};

/// The capacity of the bounded async MPMC channel used to distribute dnstap messages from
/// [`FrameHandler`]'s to [`DnstapHandler`]'s.
const CHANNEL_CAPACITY: usize = 10_000;

/// Log a periodic status update on the number of frames and bytes processed by a [`FrameHandler`]
/// every time this number of frames has been processed.
const PERIODIC_STATUS_LOG_UPDATE: usize = 100_000;

/// Maximum UDP response message size that can be received from the DNS server under test.
const DNS_RESPONSE_BUFFER_SIZE: usize = 4096;

/// Duration for [`DnstapHandler`]'s to wait for a response from the DNS server under test.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(5000);

/// The generated protobuf definitions for the dnstap protocol.
pub mod dnstap {
    #![allow(clippy::module_inception)]
    include!(concat!(env!("OUT_DIR"), "/dnstap.rs"));
}

/// Convenience Error type.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Convenience Result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Server configuration and state.
struct Server {
    /// Filesystem path to start the Unix socket listener on.
    unix_path: String,

    /// Socket address/port of the DNS server to send DNS queries to.
    server_address: SocketAddr,

    /// The number of [`DnstapHandler`]'s to start. Each handler has its own dedicated UDP client
    /// socket to send queries to the DNS server.
    num_dnstap_handlers: usize,

    /// The send side of the async channel, used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    channel_sender: async_channel::Sender<dnstap::Dnstap>,

    /// The receive side of the async channel, used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`FrameHandler`]'s.
    channel_receiver: async_channel::Receiver<dnstap::Dnstap>,
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(unix_path: &str, server_address: SocketAddr, num_dnstap_handlers: usize) -> Self {
        let (channel_sender, channel_receiver) = bounded(CHANNEL_CAPACITY);

        Server {
            unix_path: String::from(unix_path),
            server_address,
            num_dnstap_handlers,
            channel_sender,
            channel_receiver,
        }
    }

    /// Run the server. Binds a Unix socket listener to the filesystem and listens for incoming
    /// connections. Each incoming connection is handled by a newly spawned [`FrameHandler`]. Also
    /// starts up the number of [`DnstapHandler`]'s specified by the configuration. Creates an
    /// async MPMC channel for the [`FrameHandler`]'s to send message objects to the
    /// [`DnstapHandler`]'s for processing.
    async fn run(&mut self) -> Result<()> {
        let _ = std::fs::remove_file(&self.unix_path);
        let listener = UnixListener::bind(&self.unix_path)?;
        info!("Listening on Unix socket path {}", &self.unix_path);
        info!("Sending DNS queries to server {}", &self.server_address);
        info!("Using {} UDP DNS client sockets", self.num_dnstap_handlers);

        // Start up the [`DnstapHandler`]'s.
        for _ in 0..self.num_dnstap_handlers {
            // Create a new [`DnstapHandler`] and give it a cloned channel receiver.
            let mut dnstap_handler =
                DnstapHandler::new(self.channel_receiver.clone(), self.server_address).await?;

            // Spawn a new task to run the [`DnstapHandler`].
            tokio::spawn(async move {
                if let Err(err) = dnstap_handler.run().await {
                    error!("DnstapHandler error: {}", err);
                }
            });
        }

        // Accept incoming connections on the FrameStreams socket.
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    // Create a [`FrameHandler`] for this connection.
                    let mut frame_handler = FrameHandler::new(stream, self.channel_sender.clone());

                    // Spawn a new task to run the [`FrameHandler`].
                    tokio::spawn(async move {
                        if let Err(err) = frame_handler.run().await {
                            warn!("FrameHandler error: {}", err);
                        }
                    });
                }
                Err(err) => {
                    warn!("Accept error: {}", err);
                }
            }
        }
    }
}

/// Per-connection FrameStreams protocol handler. Reads delimited frames from the Unix socket
/// stream, decodes the protobuf payload, and then sends the protobuf object over a channel to a
/// [`DnstapHandler`] for further processing.
struct FrameHandler {
    /// The send side of the async channel, used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    channel_sender: async_channel::Sender<dnstap::Dnstap>,

    /// The Unix stream to read frames from.
    stream: UnixStream,

    /// Identifying description of the connected `stream`.
    stream_descr: String,

    /// Counter of the number of bytes processed by this [`FrameHandler`].
    count_data_bytes: usize,

    /// Counter of the number of frames processed by this [`FrameHandler`].
    count_data_frames: usize,
}

impl FrameHandler {
    /// Create a new [`FrameHandler`] that reads from [`stream`] and writes decoded protobuf
    /// messages to [`channel_sender`].
    pub fn new(stream: UnixStream, channel_sender: async_channel::Sender<dnstap::Dnstap>) -> Self {
        let stream_descr = format!("fd {}", stream.as_raw_fd());

        FrameHandler {
            stream,
            stream_descr,
            channel_sender,
            count_data_bytes: 0,
            count_data_frames: 0,
        }
    }

    /// Set up the FrameStreams connection and processing the incoming data frames.
    async fn run(&mut self) -> Result<()> {
        info!(
            "Accepted new Frame Streams connection on {}",
            self.stream_descr
        );

        let time_start = Instant::now();

        // Initialize the FrameStreams codec.
        let mut framed = Framed::with_capacity(
            &mut self.stream,
            FrameStreamsCodec {},
            framestreams_codec::FRAME_LENGTH_MAX,
        );

        // Process each frame from the connection.
        while let Some(frame) = framed.next().await {
            match frame {
                Ok(frame) => {
                    match frame {
                        Frame::ControlReady(payload) => {
                            // Ready: This is the first control frame received from the sender.
                            // Send the Accept control frame.
                            //
                            // XXX: We mirror the content type(s) specified in the Ready control
                            // frame payload into the Accept control frame payload. Instead we
                            // should select a specific content type from the sender's list.
                            framed.send(Frame::ControlAccept(payload)).await?;
                        }
                        Frame::ControlAccept(_) => {
                            // Accept: This is the control frame that the receiver sends in
                            // response to the Ready frame. It is a protocol violation for a sender
                            // to send an Accept control frame.
                            bail!(
                                "{}: Protocol error: Sender sent ACCEPT frame",
                                self.stream_descr
                            );
                        }
                        Frame::ControlStart(payload) => {
                            // Start: This is the control frame that the sender sends in response
                            // to the Accept frame and indicates it will begin sending data frames
                            // of the type specified in the Start control frame payload.
                            //
                            // XXX: We should probably do something with the content type that the
                            // sender specifies in the Start control frame payload.
                            trace!(
                                "{}: START payload: {}",
                                self.stream_descr,
                                Hexlify(&payload)
                            );
                        }
                        Frame::ControlStop => {
                            // Stop: This is the control frame that the sender sends when it is
                            // done sending Data frames. Send the Finish frame acknowledging
                            // shutdown of the stream.
                            info!(
                                "{}: STOP received, processed {} data frames, {} data bytes",
                                self.stream_descr, self.count_data_frames, self.count_data_bytes,
                            );
                            framed.send(Frame::ControlFinish).await?;

                            // Shut the [`FrameHandler`] down.
                            return Ok(());
                        }
                        Frame::ControlFinish => {
                            // Protocol violation for a receiver to receive a Finish control frame.
                            bail!(
                                "{}: Protocol error: Sender sent FINISH frame",
                                self.stream_descr
                            );
                        }
                        Frame::ControlUnknown(_) => {
                            bail!(
                                "{}: Protocol error: Sender sent unknown control frame",
                                self.stream_descr
                            );
                        }
                        Frame::Data(mut payload) => {
                            // Data: Let's process it.

                            // Accounting.
                            self.count_data_bytes += payload.len();
                            self.count_data_frames += 1;
                            if log_enabled!(log::Level::Debug) {
                                let time_duration = time_start.elapsed().as_secs_f64();
                                if (self.count_data_frames % PERIODIC_STATUS_LOG_UPDATE) == 0 {
                                    debug!(
                                    "{}: Processed {} data frames, {} data bytes, {} frames/sec, {} kbytes/sec",
                                    self.stream_descr,
                                    self.count_data_frames,
                                    self.count_data_bytes,
                                    (self.count_data_frames as f64 / time_duration) as usize,
                                    ((self.count_data_bytes as f64 / time_duration) / 1024.0) as usize,
                                );
                                }
                            }

                            // Decode the protobuf message.
                            match dnstap::Dnstap::decode(&mut payload) {
                                // The message was successfully parsed, send it to a
                                // [`DnstapHandler`] for further processing.
                                Ok(d) => {
                                    let _ = self.channel_sender.send(d).await;
                                }
                                // The payload failed to parse.
                                Err(e) => {
                                    bail!(
                                        "{}: Protocol error: Decoding dnstap protobuf message: {}, payload: {}",
                                        self.stream_descr,
                                        e,
                                        Hexlify(&payload)
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    bail!("{}: Protocol error: {}", self.stream_descr, e);
                }
            }
        }

        Ok(())
    }
}

/// Process the dnstap protobuf payloads and re-send them to the DNS server under test.
///
/// Decoded protobuf payloads are received over a channel from a [`FrameHandler`]. The original
/// address of the DNS client that sent the DNS query is used to construct a PROXY v2 header which
/// is prepended to the DNS query which is sent to the DNS server specified in the configuration.
/// The response that the DNS server sends is then compared to the original DNS response message
/// included in the dnstap payload and logged if they differ.
///
/// This requires two specializations:
///
/// 1. The DNS server that sends the dnstap payloads needs to produce `AUTH_RESPONSE` messages that
///    include both the `query_message` and `response_message` fields. It is optional to fill out
///    both of these fields, and DNS servers typically only fill out the `response_message` field
///    for `AUTH_RESPONSE` dnstap payloads.
/// 2. The DNS server under test needs to understand the PROXY v2 header which the
///    [`DnstapHandler`] prepends to the DNS query. An unmodified DNS server will not recognize the
///    prepended DNS queries that the [`DnstapHandler`] sends and will likely respond with the DNS
///    [`FORMERR`] or [`NOTIMP`] RCODEs.
struct DnstapHandler {
    /// The receive side of the async channel, used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`FrameHandler`]'s.
    channel_receiver: async_channel::Receiver<dnstap::Dnstap>,

    /// Socket address/port of the DNS server to send DNS queries to.
    server_address: SocketAddr,

    /// Per-handler DNS client socket to use to send DNS queries to the DNS server under test. This
    /// is an [`Option<UdpSocket>`] rather than a [`UdpSocket`] because in the case of a timeout
    /// the socket will need to be closed and reopened.
    socket: Option<UdpSocket>,

    /// Buffer to received UDP response messages from the DNS server under test.
    recv_buf: [u8; DNS_RESPONSE_BUFFER_SIZE],
}

impl DnstapHandler {
    /// Create a new [`DnstapHandler`] that receives decoded dnstap protobuf payloads from
    /// `channel_receiver`, synthesizes new DNS client queries and sends them to the DNS server
    /// under test specified by the address/port in `server_address`.
    async fn new(
        channel_receiver: async_channel::Receiver<dnstap::Dnstap>,
        server_address: SocketAddr,
    ) -> Result<Self> {
        let mut handler = DnstapHandler {
            channel_receiver,
            server_address,
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
            let local_address: SocketAddr = if self.server_address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?;

            // Bind the socket.
            let socket = UdpSocket::bind(local_address).await?;

            // Connect the socket to the DNS server under test.
            socket.connect(&self.server_address).await?;

            debug!("Connected socket to DNS server: {:?}", &socket);

            // Store the socket for use by the main processing loop.
            self.socket = Some(socket);
        }
        Ok(())
    }

    /// Close and reopen the UDP client socket.
    async fn restart_socket(&mut self) -> Result<()> {
        self.socket = None;
        self.maybe_setup_socket().await?;
        Ok(())
    }

    /// Receive dnstap protobuf payloads from a [`FrameHandler`] and perform further processing.
    async fn run(&mut self) -> Result<()> {
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
    async fn process_dnstap(&mut self, d: dnstap::Dnstap) -> Result<()> {
        // Extract the dnstap object type. Currently only "Message" objects are defined.
        if let Some(dtype) = dnstap::dnstap::Type::from_i32(d.r#type) {
            match dtype {
                // Handle a dnstap "Message" object.
                dnstap::dnstap::Type::Message => {
                    if let Some(msg) = d.message {
                        // Check if this is an `AUTH_RESPONSE` type dnstap "Message" object.
                        if let Some(dnstap::message::Type::AuthResponse) =
                            dnstap::message::Type::from_i32(msg.r#type)
                        {
                            // Perform further processing on this message. On error, log the error
                            // and close and reopen the UDP client socket.
                            if let Err(e) = self.process_dnstap_message(msg).await {
                                debug!("Error: {}", e);

                                // The call to process_dnstap_message() might have failed with a
                                // timeout, in which case we can't tell the difference between a
                                // message that has genuinely been lost and one that might still be
                                // processed by the DNS server under test and returned to us on a
                                // subsequent socket read. If the latter happens, the lockstep
                                // synchronization between a sent DNS query and a received DNS
                                // response will be lost and every subsequent comparison between
                                // originally logged response message and corresponding response
                                // message received from the DNS server under test will fail
                                // because the wrong messages are being compared.
                                //
                                // This kind of failure mode could be worked around by implementing
                                // a state table for the outbound DNS queries sent to the DNS
                                // server under test but this requires parsing some portions of the
                                // DNS header and the question section as well as garbage
                                // collection of the state table to avoid filling it with timed out
                                // queries. The easier thing to do is to close the socket and open
                                // a new one.
                                self.restart_socket().await?;
                            };
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Process a dnstap "Message" object.
    async fn process_dnstap_message(&mut self, msg: dnstap::Message) -> Result<()> {
        // Check if we have a connected UDP socket to send DNS queries to.
        let socket = match &self.socket {
            Some(socket) => socket,
            None => {
                bail!("No connected socket to send DNS queries");
            }
        };

        // Extract the `query_address` field and convert it to an [`IpAddr`]. This is the IP
        // address of the original client that sent the DNS query to the DNS server that logged the
        // dnstap message.
        let query_address = match &msg.query_address {
            Some(addr) => try_from_u8_slice_for_ipaddr(addr).unwrap(),
            None => return Ok(()),
        };

        // Extract the `query_port` field.
        let query_port = match &msg.query_port {
            Some(port) => *port as u16,
            None => return Ok(()),
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

        // Create a buffer for containing the PROXY v2 payload and the original DNS client message.
        // The PROXY v2 payload that we generate will be small (<100 bytes) and DNS query messages
        // are restricted by the protocol to a maximum size of 512 bytes.
        let mut buf = BytesMut::with_capacity(1024);

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

        // Add the original DNS query message after the PROXY v2 payload.
        buf.put_slice(query_message);

        // Freeze the buffer since it no longer needs to be mutated.
        let buf = buf.freeze();

        // Send the constructed query message to the DNS server under test.
        trace!("Sending DNS query: {}", Hexlify(&buf));
        socket.send(&buf).await?;

        // Receive the DNS response message from the DNS server under test, or wait for the DNS
        // query timeout to expire.
        match timeout(DNS_QUERY_TIMEOUT, socket.recv(&mut self.recv_buf)).await {
            Ok(res) => match res {
                Ok(n_bytes) => {
                    // A DNS response message was successfully received.
                    trace!(
                        "Received DNS response: {}",
                        Hexlify(&self.recv_buf[..n_bytes])
                    );

                    // Check if the DNS response message received from the DNS server under test is
                    // identical to the original DNS response message recorded in the dnstap
                    // message.
                    if response_message != &self.recv_buf[..n_bytes] {
                        // Mismatch, log the two varying DNS response messages for investigation.
                        warn!(
                            "Mismatch: received {} expecting {}",
                            Hexlify(&self.recv_buf[..n_bytes]),
                            Hexlify(response_message)
                        );
                    }
                }
                Err(e) => {
                    bail!("{}", e);
                }
            },
            Err(e) => {
                bail!("{}", e);
            }
        }

        Ok(())
    }
}

/// Utility function that converts a slice of bytes into an [`IpAddr`]. Slices of length 4 are
/// converted to IPv4 addresses and slices of length 16 are converted to IPv6 addresses. All other
/// slice lengths are invalid.
fn try_from_u8_slice_for_ipaddr(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        4 => {
            let mut x: [u8; 4] = [0, 0, 0, 0];
            x.copy_from_slice(value);
            Some(IpAddr::from(x))
        }
        16 => {
            let mut x: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            x.copy_from_slice(value);
            Some(IpAddr::from(x))
        }
        _ => None,
    }
}

fn main() -> Result<()> {
    let args = App::new("dnstap_replay")
        .about("Replays dnstap DNS messages to a DNS server")
        .arg(
            Arg::with_name("unix")
                .short("u")
                .long("unix")
                .value_name("PATH")
                .help("Unix socket path to listen on")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("IP:PORT")
                .help("UDP DNS server and port to send queries to")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("num-sockets")
                .short("n")
                .long("num-sockets")
                .value_name("INTEGER")
                .help("Number of UDP client sockets to use to send queries to DNS server")
                .takes_value(true)
                .default_value("10"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("verbosity level"),
        )
        .get_matches();

    stderrlog::new()
        .verbosity(args.occurrences_of("verbose") as usize)
        .module(module_path!())
        .init()
        .unwrap();

    // Collect the command-line configuration parameters.
    let unix_path = args.value_of("unix").unwrap();
    let server_address = value_t!(args, "server", SocketAddr).unwrap_or_else(|e| e.exit());
    let num_sockets = value_t!(args, "num-sockets", usize).unwrap_or_else(|e| e.exit());

    // Create a [`Server`] with the command-line parameters.
    let mut server = Server::new(unix_path, server_address, num_sockets);

    // Start the Tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { server.run().await })
}
