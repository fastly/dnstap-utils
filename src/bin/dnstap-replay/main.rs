// Copyright 2021-2023 Fastly, Inc.

use anyhow::Result;
use async_channel::{bounded, Receiver, Sender};
use clap::{ArgAction, Parser, ValueHint};
use ip_network::IpNetwork;
use log::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

/// The status file monitoring handler.
mod monitor_handler;
use monitor_handler::*;

/// The generated protobuf definitions for the dnstap protocol.
use dnstap_utils::dnstap;

/// Server configuration and state.
struct Server {
    /// Command-line options.
    opts: Opts,

    /// Channels.
    channels: Channels,
}

#[derive(Clone)]
pub struct Channels {
    /// The send side of the async channel used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`FrameHandler`]'s.
    receiver: Receiver<dnstap::Dnstap>,

    /// The send side of the async channel used by [`DnstapHandler`]'s to send error dnstap
    /// protobuf messages to the [`HttpHandler`].
    error_sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to send error dnstap
    /// protobuf messages to the [`HttpHandler`].
    error_receiver: Receiver<dnstap::Dnstap>,

    /// The send side of the async channel used by [`DnstapHandler`]'s to send timeout dnstap
    /// protobuf messages to the [`HttpHandler`].
    timeout_sender: Sender<dnstap::Dnstap>,

    /// The receive side of the async channel used by [`DnstapHandler`]'s to send timeout dnstap
    /// protobuf messages to the [`HttpHandler`].
    timeout_receiver: Receiver<dnstap::Dnstap>,
}

/// Command-line arguments.
#[derive(Parser, Clone)]
pub struct Opts {
    /// Capacity of async channel for handler payload distribution
    #[clap(long, default_value = "10000")]
    channel_capacity: usize,

    /// Capacity of async channel for /errors endpoint buffer
    #[clap(long, default_value = "100000")]
    channel_error_capacity: usize,

    /// Capacity of async channel for /timeouts endpoint buffer
    #[clap(long, default_value = "100000")]
    channel_timeout_capacity: usize,

    /// UDP DNS server and port to send queries to
    #[clap(long, name = "DNS IP:PORT")]
    dns: SocketAddr,

    /// DSCP value to set on outgoing queries
    #[clap(long,
           name = "DSCP code point",
           value_parser = clap::value_parser!(u8).range(0..63))]
    dscp: Option<u8>,

    /// HTTP server socket to listen on for stats and reporting
    #[clap(long, name = "HTTP IP:PORT")]
    http: SocketAddr,

    /// Whether to ignore UDP responses with the TC bit set
    #[clap(long)]
    ignore_tc: bool,

    /// Ignore queries from this IPv4 or IPv6 network
    #[clap(long, value_parser = clap::value_parser!(IpNetwork))]
    ignore_query_net: Vec<IpNetwork>,

    /// Number of UDP client sockets to use to send queries to DNS server
    #[clap(long, default_value = "10")]
    num_sockets: usize,

    /// Whether to add PROXY v2 header to re-sent DNS queries
    #[clap(long)]
    proxy: bool,

    /// Whether to add timespec TLV to PROXY v2 header
    #[clap(long)]
    proxy_timespec: bool,

    /// Time to delay after status files match
    #[clap(long, name = "MILLISECONDS", default_value = "5000", required = false)]
    match_status_delay: u64,

    /// Match status files to compare
    #[clap(long = "match-status-files",
           name = "STATUS-FILE",
           required = false,
           num_args(2..),
           value_parser,
           value_hint = ValueHint::FilePath)
    ]
    status_files: Vec<PathBuf>,

    /// Unix socket path to listen on
    #[clap(long, name = "PATH")]
    unix: String,

    /// Increase verbosity level
    #[clap(short, long, action = ArgAction::Count)]
    verbose: u8,
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(opts: &Opts) -> Self {
        // Create the channel for connecting [`FrameHandler`]'s and [`DnstapHandler`]'s.
        let (sender, receiver) = bounded(opts.channel_capacity);

        // Create the error channel for connecting [`DnstapHandler`]'s and the [`HttpHandler`].
        let (error_sender, error_receiver) = bounded(opts.channel_error_capacity);

        // Create the timeout channel for connecting [`DnstapHandler`]'s and the [`HttpHandler`].
        let (timeout_sender, timeout_receiver) = bounded(opts.channel_timeout_capacity);

        Server {
            opts: opts.clone(),
            channels: Channels {
                sender,
                receiver,
                error_sender,
                error_receiver,
                timeout_sender,
                timeout_receiver,
            },
        }
    }

    /// Run the server. Binds a Unix socket listener to the filesystem and listens for incoming
    /// connections. Each incoming connection is handled by a newly spawned [`FrameHandler`].
    ///
    /// Also starts up the [`HttpHandler`] and the number of [`DnstapHandler`]'s specified by the
    /// configuration. Each [`DnstapHandler`] creates its own UDP query socket for querying the
    /// configured DNS server.
    async fn run(&mut self) -> Result<()> {
        let match_status = Arc::new(AtomicBool::new(false));

        // Start up the [`MonitorHandler'].
        if !self.opts.status_files.is_empty() {
            let match_status_mh = match_status.clone();
            let mut monitor_handler =
                MonitorHandler::new(&self.opts.status_files, self.opts.match_status_delay)?;
            tokio::spawn(async move {
                if let Err(err) = monitor_handler.run(match_status_mh).await {
                    error!("Monitor handler error: {}", err);
                }
            });
        } else {
            match_status.store(true, Ordering::Relaxed);
            crate::metrics::MATCH_STATUS.set(1);
        }

        // Start up the [`HttpHandler`].
        let http_handler = HttpHandler::new(self.opts.http, &self.channels);
        tokio::spawn(async move {
            if let Err(err) = http_handler.run().await {
                error!("Hyper HTTP server error: {}", err);
            }
        });

        // Start up the [`DnstapHandler`]'s.
        for _ in 0..self.opts.num_sockets {
            let match_status_dh = match_status.clone();

            // Create a new [`DnstapHandler`] and give it a cloned channel receiver.
            let mut dnstap_handler =
                DnstapHandler::new(&self.opts, &self.channels, match_status_dh).await?;

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
                    let mut frame_handler = FrameHandler::new(stream, self.channels.sender.clone());

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
        .verbosity(opts.verbose as usize)
        .module(module_path!())
        .init()
        .unwrap();

    metrics::initialize_metrics();

    let mut server = Server::new(&opts);

    // Start the Tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { server.run().await })
}
