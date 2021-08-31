// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use async_channel::bounded;
use clap::{value_t, App, Arg};
use log::*;
use std::net::SocketAddr;
use tokio::net::UnixListener;

pub mod counters;

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

/// The capacity of the bounded async MPMC channel used to distribute dnstap messages from
/// [`FrameHandler`]'s to [`DnstapHandler`]'s.
const CHANNEL_CAPACITY: usize = 10_000;

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

    /// The send side of the async channel, used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    channel_sender: async_channel::Sender<dnstap::Dnstap>,

    /// The receive side of the async channel, used by [`DnstapHandler`]'s to receive decoded
    /// dnstap messages from the [`FrameHandler`]'s.
    channel_receiver: async_channel::Receiver<dnstap::Dnstap>,
}

impl Server {
    /// Create a new [`Server`] and prepare its state.
    pub fn new(
        unix_path: &str,
        dns_address: SocketAddr,
        http_address: SocketAddr,
        num_dnstap_handlers: usize,
    ) -> Self {
        let (channel_sender, channel_receiver) = bounded(CHANNEL_CAPACITY);

        Server {
            unix_path: String::from(unix_path),
            dns_address,
            http_address,
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
        info!("Sending DNS queries to server {}", &self.dns_address);
        info!("Using {} UDP DNS client sockets", self.num_dnstap_handlers);

        // Start up the [`HttpHandler`].
        let mut http_handler = HttpHandler::new(self.http_address);
        tokio::spawn(async move {
            if let Err(err) = http_handler.run().await {
                error!("Hyper HTTP server error: {}", err);
            }
        });

        // Start up the [`DnstapHandler`]'s.
        for _ in 0..self.num_dnstap_handlers {
            // Create a new [`DnstapHandler`] and give it a cloned channel receiver.
            let mut dnstap_handler =
                DnstapHandler::new(self.channel_receiver.clone(), self.dns_address).await?;

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

    // Collect the command-line configuration parameters.
    let unix = args.value_of("unix").unwrap();
    let dns = value_t!(args, "dns", SocketAddr).unwrap_or_else(|e| e.exit());
    let http = value_t!(args, "http", SocketAddr).unwrap_or_else(|e| e.exit());
    let n_sockets = value_t!(args, "num-sockets", usize).unwrap_or_else(|e| e.exit());

    // Create a [`Server`] with the command-line parameters.
    let mut server = Server::new(unix, dns, http, n_sockets);

    // Start the Tokio runtime.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { server.run().await })
}
