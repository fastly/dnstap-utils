// Copyright 2021 Fastly, Inc.

use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use clap::{Parser, ValueHint};
use heck::ShoutySnekCase;
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
use dnstap_utils::util::try_from_u8_slice_for_ipaddr;
use dnstap_utils::util::DnstapHandlerError;

#[derive(Parser, Debug)]
struct Opts {
    /// Read dnstap data from file
    #[clap(short = 'r',
           long = "read",
           name = "FILE",
           parse(from_os_str),
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
            s.push_str("  query_time: !!timestamp ");
            s.push_str(
                &NaiveDateTime::from_timestamp(query_time_sec, msg.query_time_nsec.unwrap_or(0))
                    .to_string(),
            );
            s.push('\n');
        }
    }

    if let Some(response_time_sec) = msg.response_time_sec {
        if let Ok(response_time_sec) = i64::try_from(response_time_sec) {
            s.push_str("  response_time: !!timestamp ");
            s.push_str(
                &NaiveDateTime::from_timestamp(
                    response_time_sec,
                    msg.response_time_nsec.unwrap_or(0),
                )
                .to_string(),
            );
            s.push('\n');
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

fn fmt_dns_message(s: &mut String, prefix: &str, raw_msg_bytes: &[u8]) {
    use domain::base::iana::rtype::Rtype;
    use domain::base::Message;
    use domain::rdata::AllRecordData;

    let msg = match Message::from_octets(raw_msg_bytes) {
        Ok(msg) => msg,
        Err(err) => {
            s.push_str(prefix);
            s.push_str(";; PARSE ERROR: ");
            s.push_str(&err.to_string());
            s.push('\n');
            return;
        }
    };

    let hdr = msg.header();

    // opcode
    s.push_str(prefix);
    s.push_str(";; ->>HEADER<<- opcode: ");
    s.push_str(&hdr.opcode().to_string());

    // rcode
    s.push_str(", rcode: ");
    s.push_str(&hdr.rcode().to_string());

    // id
    s.push_str(", id: ");
    s.push_str(&hdr.id().to_string());
    s.push('\n');

    // flags
    s.push_str(prefix);
    s.push_str(";; flags: ");
    if hdr.qr() {
        s.push_str("qr ");
    }
    if hdr.aa() {
        s.push_str("aa ");
    }
    if hdr.tc() {
        s.push_str("tc ");
    }
    if hdr.rd() {
        s.push_str("rd ");
    }
    if hdr.ra() {
        s.push_str("ra ");
    }
    if hdr.ad() {
        s.push_str("ad ");
    }
    if hdr.cd() {
        s.push_str("cd ");
    }

    // header counts
    let hdr_counts = msg.header_counts();
    s.push_str("; QUERY: ");
    s.push_str(&hdr_counts.qdcount().to_string());
    s.push_str(", ANSWER: ");
    s.push_str(&hdr_counts.ancount().to_string());
    s.push_str(", AUTHORITY: ");
    s.push_str(&hdr_counts.nscount().to_string());
    s.push_str(", ADDITIONAL: ");
    s.push_str(&hdr_counts.adcount().to_string());
    s.push_str("\n\n");

    if let Ok(sections) = msg.sections() {
        s.push_str(prefix);
        s.push_str(";; QUESTION SECTION:\n");
        for question in sections.0.flatten() {
            s.push_str(prefix);
            s.push(';');
            s.push_str(&question.qname().to_string());
            s.push_str(". ");
            s.push_str(&question.qclass().to_string());
            s.push(' ');
            s.push_str(&question.qtype().to_string());
            s.push('\n')
        }
        s.push('\n');

        s.push_str(prefix);
        s.push_str(";; ANSWER SECTION:\n");
        for record in sections.1.limit_to::<AllRecordData<_, _>>().flatten() {
            s.push_str(prefix);
            s.push_str(&record.to_string());
            s.push('\n')
        }
        s.push('\n');

        s.push_str(prefix);
        s.push_str(";; AUTHORITY SECTION:\n");
        for record in sections.2.limit_to::<AllRecordData<_, _>>().flatten() {
            s.push_str(prefix);
            s.push_str(&record.to_string());
            s.push('\n')
        }
        s.push('\n');

        s.push_str(prefix);
        s.push_str(";; ADDITIONAL SECTION:\n");
        for record in sections.3.limit_to::<AllRecordData<_, _>>().flatten() {
            if record.rtype() == Rtype::Opt {
                continue;
            }
            s.push_str(prefix);
            s.push_str(&record.to_string());
            s.push('\n')
        }

        if let Some(opt) = msg.opt() {
            s.push('\n');
            s.push_str(prefix);
            s.push_str(";; EDNS: version ");
            s.push_str(&opt.version().to_string());
            s.push_str("; flags: ");
            if opt.dnssec_ok() {
                s.push_str("do ");
            }
            s.push_str("; udp: ");
            s.push_str(&opt.udp_payload_size().to_string());
            s.push('\n');
        }
    }
}
