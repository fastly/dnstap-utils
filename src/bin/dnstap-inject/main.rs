// Copyright 2021-2024 Fastly, Inc.

use anyhow::{bail, Result};
use bytes::{BufMut, BytesMut};
use clap::{ArgAction, Parser, ValueHint};
use log::*;
use prost::Message;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use dnstap_utils::dnstap;
use dnstap_utils::framestreams_codec::{Frame, FrameStreamsCodec};
use dnstap_utils::proxyv2;
use dnstap_utils::util::try_from_u8_slice_for_ipaddr;

/// Duration to wait for a response from the DNS server under test.
const DNS_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Parser, Debug)]
struct Opts {
    /// Read dnstap data from file
    #[clap(short = 'r',
           long = "read",
           name = "FILE",
           value_parser,
           value_hint = ValueHint::FilePath)
    ]
    file: PathBuf,

    /// UDP DNS server and port to send queries to
    #[clap(long, name = "DNS IP:PORT")]
    dns: SocketAddr,

    /// Whether to add PROXY v2 header to re-sent DNS queries
    #[clap(long)]
    proxy: bool,

    /// Increase verbosity level
    #[clap(short, long, action = ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Workaround for https://github.com/rust-lang/rust/issues/62569
    if cfg!(unix) {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    let opts = Opts::parse();

    stderrlog::new()
        .verbosity(opts.verbose as usize)
        .module(module_path!())
        .init()
        .unwrap();

    let file = File::open(opts.file).await?;
    let socket = setup_socket(&opts.dns).await?;

    let mut framed = Framed::new(file, FrameStreamsCodec {});
    while let Some(frame) = framed.next().await {
        match frame {
            Ok(frame) => match frame {
                Frame::ControlReady(_) => {
                    bail!("Protocol error: READY frame not allowed here");
                }
                Frame::ControlAccept(_) => {
                    bail!("Protocol error: ACCEPT frame not allowed here");
                }
                Frame::ControlStart(_) => {
                    // XXX: Validate the content type embedded in the Start control frame payload.
                }
                Frame::ControlStop => {
                    return Ok(());
                }
                Frame::ControlFinish => {
                    bail!("Protocol error: FINISH frame not allowed here");
                }
                Frame::ControlUnknown(_) => {
                    bail!("Protocol error: Unknown control frame");
                }
                Frame::Data(mut payload) => match dnstap::Dnstap::decode(&mut payload) {
                    Ok(d) => {
                        process_dnstap_frame(&socket, opts.proxy, d).await?;
                    }
                    Err(e) => {
                        bail!(
                            "Protocol error: Decoding dnstap protobuf message: {}, payload: {}",
                            e,
                            hex::encode(&payload)
                        );
                    }
                },
            },
            Err(e) => {
                bail!("Protocol error: {}", e);
            }
        }
    }

    Ok(())
}

async fn setup_socket(server_addr: &SocketAddr) -> Result<UdpSocket> {
    let local_addr: SocketAddr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;

    let socket = UdpSocket::bind(local_addr).await?;
    socket.connect(server_addr).await?;
    debug!("Connected socket to DNS server: {:?}", &socket);
    Ok(socket)
}

async fn process_dnstap_frame(socket: &UdpSocket, proxy: bool, d: dnstap::Dnstap) -> Result<()> {
    if let Ok(dtype) = dnstap::dnstap::Type::try_from(d.r#type) {
        if dtype == dnstap::dnstap::Type::Message {
            if let Some(msg) = &d.message {
                process_dnstap_message(socket, proxy, msg).await?;
            }
        }
    }

    Ok(())
}

async fn process_dnstap_message(
    socket: &UdpSocket,
    proxy: bool,
    msg: &dnstap::Message,
) -> Result<()> {
    if let Some(query_address) = &msg.query_address {
        if let Ok(query_address) = try_from_u8_slice_for_ipaddr(query_address) {
            if msg.query_message.is_some() {
                send_query(socket, proxy, &query_address, msg).await?;
            }
        }
    }
    Ok(())
}

async fn send_query(
    socket: &UdpSocket,
    proxy: bool,
    query_address: &IpAddr,
    msg: &dnstap::Message,
) -> Result<()> {
    if let Some(query_message) = &msg.query_message {
        // Buffer to received UDP response messages from the DNS server under test.
        let mut recv_buf: [u8; 4096] = [0; 4096];

        // Create a buffer for containing the original DNS query message, optionally with a PROXY v2
        // header prepended.
        let mut buf = BytesMut::with_capacity(1024);

        if proxy {
            proxyv2::add_proxy_payload(&mut buf, msg, query_address, None)?;
        }

        // Add the original DNS query message.
        buf.put_slice(query_message);

        // Freeze the buffer since it no longer needs to be mutated.
        let buf = buf.freeze();

        // Send the constructed query message to the DNS server under test.
        trace!("Sending DNS query: {}", hex::encode(query_message));
        socket.send(&buf).await?;

        // Receive the DNS response message from the DNS server under test, or wait for the DNS
        // query timeout to expire.
        match timeout(DNS_QUERY_TIMEOUT, socket.recv(&mut recv_buf)).await {
            Ok(res) => match res {
                Ok(n_bytes) => {
                    let received_message = &recv_buf[..n_bytes];
                    trace!("Received DNS response: {}", hex::encode(received_message));
                }
                Err(e) => {
                    error!("Error while receiving response: {}", e);
                }
            },
            Err(e) => {
                error!("Timeout: {}", e);
            }
        }
    }

    Ok(())
}
