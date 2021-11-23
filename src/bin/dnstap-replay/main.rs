// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use async_channel::{bounded, Receiver, Sender};
use clap::Parser;
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

    /// The send side of the async channel used by [`DnstapHandler`]'s to send error dnstap
    /// protobuf messages to the [`HttpHandler`].
    channel_error_sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to send error dnstap
    /// protobuf messages to the [`HttpHandler`].
    channel_error_receiver: Receiver<dnstap::Dnstap>,
}

/// Command-line arguments.
#[derive(Parser, Clone)]
struct Opts {
    /// Capacity of async channel for handler payload distribution
    #[clap(long, default_value = "10000")]
    channel_capacity: usize,

    /// Capacity of async channel for /errors endpoint buffer
    #[clap(long, default_value = "100000")]
    channel_error_capacity: usize,

    /// UDP DNS server and port to send queries to
    #[clap(long, name = "DNS IP:PORT")]
    dns: SocketAddr,

    /// DSCP value to set on outgoing queries
    #[clap(long, name = "DSCP code point", validator = is_dscp)]
    dscp: Option<u8>,

    /// HTTP server socket to listen on for stats and reporting
    #[clap(long, name = "HTTP IP:PORT")]
    http: SocketAddr,

    /// Number of UDP client sockets to use to send queries to DNS server
    #[clap(long, default_value = "10")]
    num_sockets: usize,

    /// Whether to add PROXY v2 header to re-sent DNS queries
    #[clap(long)]
    proxy: bool,

    /// Unix socket path to listen on
    #[clap(long, name = "PATH")]
    unix: String,

    /// Increase verbosity level
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

#[cfg(unix)]
fn is_dscp(val: &str) -> Result<(), String> {
    // Parse 'val' as an integer, but only allow values between 0 and 63 inclusive since the DSCP
    // field is a 6-bit quantity.
    match val.parse() {
        Ok(0..=63) => Ok(()),
        _ => Err(String::from("DSCP code point must be in the range [0..63]")),
    }
}

#[cfg(not(unix))]
fn is_dscp(_val: &str) -> Result<(), String> {
    Err(String::from("Cannot set DSCP values on this platform"))
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(opts: &Opts) -> Self {
        // Create the channel for connecting [`FrameHandler`]'s and [`DnstapHandler`]'s.
        let (channel_sender, channel_receiver) = bounded(opts.channel_capacity);

        // Create the channel for connecting [`DnstapHandler`]'s and the [`HttpHandler`].
        let (channel_error_sender, channel_error_receiver) = bounded(opts.channel_error_capacity);

        Server {
            opts: opts.clone(),
            channel_sender,
            channel_receiver,
            channel_error_sender,
            channel_error_receiver,
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
        let http_handler = HttpHandler::new(self.opts.http, self.channel_error_receiver.clone());
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
                self.channel_error_sender.clone(),
                self.opts.dns,
                self.opts.proxy,
                self.opts.dscp,
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
        if self.opts.proxy {
            info!("Sending DNS queries with PROXY v2 header");
        }
        if let Some(dscp) = self.opts.dscp {
            info!("Sending DNS queries with DSCP value {}", dscp);
        }

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
