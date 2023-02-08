// Copyright 2021-2023 Fastly, Inc.

use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use clap::{Parser, ValueHint};
use heck::ToShoutySnekCase;
use prost::Message;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::Write;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use dnstap_utils::dnstap;
use dnstap_utils::framestreams_codec::{Frame, FrameStreamsCodec};
use dnstap_utils::util::deserialize_dnstap_handler_error;
use dnstap_utils::util::fmt_dns_message;
use dnstap_utils::util::try_from_u8_slice_for_ipaddr;
use dnstap_utils::util::DnstapHandlerError;

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
    let file = File::open(opts.file).await?;
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
                        let mut s = String::with_capacity(2048);
                        fmt_dnstap(&mut s, d);
                        s.push_str("---\n");
                        std::io::stdout().write_all(s.as_bytes()).unwrap();
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

fn fmt_dnstap(s: &mut String, d: dnstap::Dnstap) {
    if let Some(dtype) = dnstap::dnstap::Type::from_i32(d.r#type) {
        s.push_str("type: ");
        s.push_str(&format!("{:?}", dtype).TO_SHOUTY_SNEK_CASE());
        s.push('\n');
    }

    if let Some(identity) = &d.identity {
        s.push_str("identity: \"");
        s.push_str(&String::from_utf8_lossy(identity));
        s.push_str("\"\n");
    }

    if let Some(version) = &d.version {
        s.push_str("version: \"");
        s.push_str(&String::from_utf8_lossy(version));
        s.push_str("\"\n");
    }

    if let Some(extra) = &d.extra {
        s.push_str("extra:\n");

        s.push_str("  bytes: \"");
        s.push_str(&hex::encode(extra));
        s.push_str("\"\n");

        s.push_str("  type: ");

        // Attempt to deserialize the dnstap payload's 'extra' field as if it were a serialized
        // DnstapHandler error. The 'extra' field in dnstap payloads "can be used for adding an
        // arbitrary byte-string annotation to the payload. No encoding or interpretation is
        // applied or enforced.", according to the dnstap protobuf definition.
        //
        // The custom serialization of DnstapHandler errors has a unique prefix which allows them
        // to be distinguished from other uses of the 'extra' field.
        match deserialize_dnstap_handler_error(extra) {
            Ok(dhe) => match dhe {
                DnstapHandlerError::Mismatch(mismatch_dns_bytes, _, _) => {
                    s.push_str("DRDH_MISMATCH\n");
                    s.push_str("  mismatch_bytes: \"");
                    s.push_str(&hex::encode(&mismatch_dns_bytes));
                    s.push_str("\"\n");
                    s.push_str("  mismatch_formatted: |\n");
                    fmt_dns_message(s, "    ", &mismatch_dns_bytes);
                }
                DnstapHandlerError::Timeout => {
                    s.push_str("DRDH_TIMEOUT\n");
                }
                DnstapHandlerError::MissingField => {
                    s.push_str("DRDH_MISSING_FIELD\n");
                }
            },
            Err(_) => {
                s.push_str("DRDH_EXTRA_PAYLOAD_PARSE_ERROR\n");
            }
        }
    }

    if let Some(msg) = &d.message {
        fmt_dnstap_message(s, msg);
    }
}

fn fmt_dnstap_message(s: &mut String, msg: &dnstap::Message) {
    s.push_str("message:\n");

    s.push_str("  type: ");
    s.push_str(&format!("{:?}", msg.r#type()).TO_SHOUTY_SNEK_CASE());
    s.push('\n');

    if let Some(query_time_sec) = msg.query_time_sec {
        if let Ok(query_time_sec) = i64::try_from(query_time_sec) {
            if let Some(dt) =
                NaiveDateTime::from_timestamp_opt(query_time_sec, msg.query_time_nsec())
            {
                s.push_str("  query_time: !!timestamp ");
                s.push_str(&dt.to_string());
                s.push('\n');
            }
        }
    }

    if let Some(response_time_sec) = msg.response_time_sec {
        if let Ok(response_time_sec) = i64::try_from(response_time_sec) {
            if let Some(dt) =
                NaiveDateTime::from_timestamp_opt(response_time_sec, msg.response_time_nsec())
            {
                s.push_str("  response_time: !!timestamp ");
                s.push_str(&dt.to_string());
                s.push('\n');
            }
        }
    }

    if msg.socket_family.is_some() {
        s.push_str("  socket_family: ");
        s.push_str(&format!("{:?}", msg.socket_family()).TO_SHOUTY_SNEK_CASE());
        s.push('\n');
    }

    if msg.socket_protocol.is_some() {
        s.push_str("  socket_protocol: ");
        s.push_str(&format!("{:?}", msg.socket_protocol()).TO_SHOUTY_SNEK_CASE());
        s.push('\n');
    }

    if let Some(query_address) = &msg.query_address {
        if let Ok(query_address) = try_from_u8_slice_for_ipaddr(query_address) {
            s.push_str("  query_address: \"");
            s.push_str(&query_address.to_string());
            s.push_str("\"\n");
        }
    }

    if let Some(response_address) = &msg.response_address {
        if let Ok(response_address) = try_from_u8_slice_for_ipaddr(response_address) {
            s.push_str("  response_address: \"");
            s.push_str(&response_address.to_string());
            s.push_str("\"\n");
        }
    }

    if let Some(query_port) = &msg.query_port {
        s.push_str("  query_port: ");
        s.push_str(&query_port.to_string());
        s.push('\n');
    }

    if let Some(response_port) = &msg.response_port {
        s.push_str("  response_port: ");
        s.push_str(&response_port.to_string());
        s.push('\n');
    }

    if let Some(query_message) = &msg.query_message {
        s.push_str("  query_message_bytes: \"");
        s.push_str(&hex::encode(query_message));
        s.push_str("\"\n");

        s.push_str("  query_message_formatted: |\n");
        fmt_dns_message(s, "    ", query_message);
    }

    if let Some(response_message) = &msg.response_message {
        s.push_str("  response_message_bytes: \"");
        s.push_str(&hex::encode(response_message));
        s.push_str("\"\n");

        s.push_str("  response_message_formatted: |\n");
        fmt_dns_message(s, "    ", response_message);
    }
}
