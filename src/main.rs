// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use async_channel::{bounded, Receiver, Sender};
use clap::{value_t, App, Arg};
use log::*;
use std::net::SocketAddr;
use tokio::net::UnixListener;

/// Prometheus metrics.
pub mod metrics;

/// The dnstap payload processing handler.
mod dnstap_handler;
use dnstap_handler::*;

/// The Frame Streams connection processing handler.
mod frame_handler;
use frame_handler::*;

/// The HTTP server for stats and reporting.
mod http_handler;
use http_handler::*;

/// The codec for handshaking and decoding the "Frame Streams" protocol used by dnstap.
pub mod framestreams_codec;

/// The generated protobuf definitions for the dnstap protocol.
pub mod dnstap {
    #![allow(clippy::module_inception)]
    include!(concat!(env!("OUT_DIR"), "/dnstap.rs"));
}

/// Server configuration and state.
struct Server {
    /// Filesystem path to start the Unix socket listener on.
    unix_path: String,

    /// Socket address/port of the DNS server to send DNS queries to.
    dns_address: SocketAddr,

    /// Socket address/port to listen on for HTTP stats and reporting
    http_address: SocketAddr,

    /// The number of [`DnstapHandler`]'s to start. Each handler has its own dedicated UDP client
    /// socket to send queries to the DNS server.
    num_dnstap_handlers: usize,

    /// The send side of the async channel used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    channel_sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`FrameHandler`]'s.
    channel_receiver: Receiver<dnstap::Dnstap>,

    /// The send side of the async channel used by [`DnstapHandler`]'s to send mismatch dnstap
    /// protobuf messages to the [`HttpHandler`].
    channel_mismatch_sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to send mismatch dnstap
    /// protobuf messages to the [`HttpHandler`].
    channel_mismatch_receiver: Receiver<dnstap::Dnstap>,
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(
        unix_path: &str,
        dns_address: SocketAddr,
        http_address: SocketAddr,
        num_dnstap_handlers: usize,
        channel_capacity: usize,
        channel_mismatch_capacity: usize,
    ) -> Self {
        // Create the channel for connecting [`FrameHandler`]'s and [`DnstapHandler`]'s.
        let (channel_sender, channel_receiver) = bounded(channel_capacity);

        // Create the channel for connecting [`DnstapHandler`]'s and the [`HttpHandler`].
        let (channel_mismatch_sender, channel_mismatch_receiver) =
            bounded(channel_mismatch_capacity);

        Server {
            unix_path: String::from(unix_path),
            dns_address,
            http_address,
            num_dnstap_handlers,
            channel_sender,
            channel_receiver,
            channel_mismatch_sender,
            channel_mismatch_receiver,
        }
    }

    /// Run the server. Binds a Unix socket listener to the filesystem and listens for incoming
    /// connections. Each incoming connection is handled by a newly spawned [`FrameHandler`].
    ///
    /// Also starts up the [`HttpHandler`] and the number of [`DnstapHandler`]'s specified by the
    /// configuration. Each [`DnstapHandler`] creates its own UDP query socket for querying the
    /// configured DNS server.
    async fn run(&mut self) -> Result<()> {
        // Start up the [`HttpHandler`].
        let http_handler =
            HttpHandler::new(self.http_address, self.channel_mismatch_receiver.clone());
        tokio::spawn(async move {
            if let Err(err) = http_handler.run().await {
                error!("Hyper HTTP server error: {}", err);
            }
        });

        // Start up the [`DnstapHandler`]'s.
        for _ in 0..self.num_dnstap_handlers {
            // Create a new [`DnstapHandler`] and give it a cloned channel receiver.
            let mut dnstap_handler = DnstapHandler::new(
                self.channel_receiver.clone(),
                self.channel_mismatch_sender.clone(),
                self.dns_address,
            )
            .await?;

            // Spawn a new task to run the [`DnstapHandler`].
            tokio::spawn(async move {
                if let Err(err) = dnstap_handler.run().await {
                    error!("DnstapHandler error: {}", err);
                }
            });
        }
        info!(
            "Sending DNS queries to server {} using {} UDP query sockets",
            &self.dns_address, self.num_dnstap_handlers
        );

        // Bind to the configured Unix socket. Remove the socket file if it exists.
        let _ = std::fs::remove_file(&self.unix_path);
        let listener = UnixListener::bind(&self.unix_path)?;
        info!("Listening on Unix socket path {}", &self.unix_path);

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

fn main() -> Result<()> {
    let args = App::new("dnstap_replay")
        .about("Replays dnstap DNS messages to a DNS server")
        .arg(
            Arg::with_name("channel-capacity")
                .long("channel-capacity")
                .value_name("NUM_PAYLOADS")
                .help("Capacity of async channel for handler payload distribution")
                .takes_value(true)
                .default_value("10000"),
        )
        .arg(
            Arg::with_name("channel-mismatch-capacity")
                .long("channel-mismatch-capacity")
                .value_name("NUM_PAYLOADS")
                .help("Capacity of async channel for /mismatches endpoint buffer")
                .takes_value(true)
                .default_value("100000"),
        )
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
            Arg::with_name("http")
                .short("t")
                .long("http")
                .value_name("IP:PORT")
                .help("HTTP server socket to listen on for stats and reporting")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("dns")
                .short("d")
                .long("dns")
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

    // Create a [`Server`] with the command-line parameters.
    let mut server = Server::new(
        &value_t!(args, "unix", String).unwrap_or_else(|e| e.exit()),
        value_t!(args, "dns", SocketAddr).unwrap_or_else(|e| e.exit()),
        value_t!(args, "http", SocketAddr).unwrap_or_else(|e| e.exit()),
        value_t!(args, "num-sockets", usize).unwrap_or_else(|e| e.exit()),
        value_t!(args, "channel-capacity", usize).unwrap_or_else(|e| e.exit()),
        value_t!(args, "channel-mismatch-capacity", usize).unwrap_or_else(|e| e.exit()),
    );

    // Start the Tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { server.run().await })
}
