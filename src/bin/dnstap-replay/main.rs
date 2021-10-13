// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use async_channel::{bounded, Receiver, Sender};
use clap::Clap;
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
use dnstap_utils::framestreams_codec;

/// The generated protobuf definitions for the dnstap protocol.
use dnstap_utils::dnstap;

/// Server configuration and state.
struct Server {
    /// Command-line options.
    opts: Opts,

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

/// Command-line arguments.
#[derive(Clap, Clone)]
struct Opts {
    #[clap(
        long,
        about = "Capacity of async channel for handler payload distribution",
        default_value = "10000"
    )]
    channel_capacity: usize,

    #[clap(
        long,
        about = "Capacity of async channel for /mismatches endpoint buffer",
        default_value = "100000"
    )]
    channel_mismatch_capacity: usize,

    #[clap(
        long,
        name = "DNS IP:PORT",
        about = "UDP DNS server and port to send queries to"
    )]
    dns: SocketAddr,

    #[clap(
        long,
        name = "HTTP IP:PORT",
        about = "HTTP server socket to listen on for stats and reporting"
    )]
    http: SocketAddr,

    #[clap(
        long,
        about = "Number of UDP client sockets to use to send queries to DNS server",
        default_value = "10"
    )]
    num_sockets: usize,

    #[clap(long, name = "PATH", about = "Unix socket path to listen on")]
    unix: String,

    #[clap(
        short,
        long,
        about = "Increase verbosity level",
        parse(from_occurrences)
    )]
    verbose: usize,
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(opts: &Opts) -> Self {
        // Create the channel for connecting [`FrameHandler`]'s and [`DnstapHandler`]'s.
        let (channel_sender, channel_receiver) = bounded(opts.channel_capacity);

        // Create the channel for connecting [`DnstapHandler`]'s and the [`HttpHandler`].
        let (channel_mismatch_sender, channel_mismatch_receiver) =
            bounded(opts.channel_mismatch_capacity);

        Server {
            opts: opts.clone(),
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
        let http_handler = HttpHandler::new(self.opts.http, self.channel_mismatch_receiver.clone());
        tokio::spawn(async move {
            if let Err(err) = http_handler.run().await {
                error!("Hyper HTTP server error: {}", err);
            }
        });

        // Start up the [`DnstapHandler`]'s.
        for _ in 0..self.opts.num_sockets {
            // Create a new [`DnstapHandler`] and give it a cloned channel receiver.
            let mut dnstap_handler = DnstapHandler::new(
                self.channel_receiver.clone(),
                self.channel_mismatch_sender.clone(),
                self.opts.dns,
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
            &self.opts.dns, self.opts.num_sockets,
        );

        // Bind to the configured Unix socket. Remove the socket file if it exists.
        let _ = std::fs::remove_file(&self.opts.unix);
        let listener = UnixListener::bind(&self.opts.unix)?;
        info!("Listening on Unix socket path {}", &self.opts.unix);

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
    let opts = Opts::parse();

    stderrlog::new()
        .verbosity(opts.verbose)
        .module(module_path!())
        .init()
        .unwrap();

    let mut server = Server::new(&opts);

    // Start the Tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { server.run().await })
}
