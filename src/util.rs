// Copyright 2021 Fastly, Inc.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use domain::base::opt::AllOptData;
use std::convert::TryFrom;
use std::net::IpAddr;
use thiserror::Error;

/// Utility function that converts a slice of bytes into an [`IpAddr`]. Slices of length 4 are
/// converted to IPv4 addresses and slices of length 16 are converted to IPv6 addresses. All other
/// slice lengths are invalid. This is how IP addresses are encoded in dnstap protobuf messages.
pub fn try_from_u8_slice_for_ipaddr(value: &[u8]) -> Result<IpAddr> {
    match value.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(value)?)),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(value)?)),
        _ => bail!(
            "Cannot decode an IP address from a {} byte field",
            value.len()
        ),
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum DnstapHandlerError {
    #[error("Mismatch between logged dnstap response and re-queried DNS response, expecting {1} but received {2}")]
    Mismatch(Bytes, String, String),

    #[error("Timeout sending DNS query")]
    Timeout,

    #[error("dnstap payload is missing a required field")]
    MissingField,
}

const DNSTAP_HANDLER_ERROR_PREFIX: &[u8] = b"dnstap-replay/DnstapHandlerError\x00";

impl DnstapHandlerError {
    pub fn serialize(&self) -> Bytes {
        match self {
            DnstapHandlerError::Mismatch(mismatch, _, _) => {
                let mut b =
                    BytesMut::with_capacity(DNSTAP_HANDLER_ERROR_PREFIX.len() + 4 + mismatch.len());
                b.extend_from_slice(DNSTAP_HANDLER_ERROR_PREFIX);
                b.put_u32(1);
                b.extend_from_slice(mismatch);
                b
            }
            DnstapHandlerError::Timeout => {
                let mut b = BytesMut::with_capacity(DNSTAP_HANDLER_ERROR_PREFIX.len() + 4);
                b.extend_from_slice(DNSTAP_HANDLER_ERROR_PREFIX);
                b.put_u32(2);
                b
            }
            DnstapHandlerError::MissingField => {
                let mut b = BytesMut::with_capacity(DNSTAP_HANDLER_ERROR_PREFIX.len() + 4);
                b.extend_from_slice(DNSTAP_HANDLER_ERROR_PREFIX);
                b.put_u32(3);
                b
            }
        }
        .freeze()
    }
}

pub fn deserialize_dnstap_handler_error(input: &[u8]) -> Result<DnstapHandlerError> {
    if input.len() < DNSTAP_HANDLER_ERROR_PREFIX.len() {
        bail!("Input buffer is too small");
    }

    let mut buf = Bytes::copy_from_slice(input);

    let prefix = buf.copy_to_bytes(DNSTAP_HANDLER_ERROR_PREFIX.len());
    if prefix != DNSTAP_HANDLER_ERROR_PREFIX {
        bail!("DnstapHandlerError prefix not present");
    }

    if buf.remaining() < 4 {
        bail!("DnstapHandlerError type not present");
    }

    match buf.get_u32() {
        1 => Ok(DnstapHandlerError::Mismatch(
            buf.split_off(0),
            String::from(""),
            String::from(""),
        )),
        2 => Ok(DnstapHandlerError::Timeout),
        3 => Ok(DnstapHandlerError::MissingField),
        _ => {
            bail!("Unknown DnstapHandlerError type");
        }
    }
}

#[test]
fn test_deserialize_dnstap_handler_error() {
    // Test the extreme boundary condition. This is a minimally sized serialized
    // DnstapHandlerError::Mismatch.
    assert_eq!(
        deserialize_dnstap_handler_error(b"dnstap-replay/DnstapHandlerError\x00\x00\x00\x00\x01")
            .unwrap(),
        DnstapHandlerError::Mismatch(Bytes::from(&b""[..]), String::from(""), String::from(""))
    );

    // This is the smallest serialized DnstapHandlerError::Mismatch with a single byte payload.
    assert_eq!(
        deserialize_dnstap_handler_error(
            b"dnstap-replay/DnstapHandlerError\x00\x00\x00\x00\x01\x42"
        )
        .unwrap(),
        DnstapHandlerError::Mismatch(
            Bytes::from(&b"\x42"[..]),
            String::from(""),
            String::from("")
        )
    );

    // The only way to serialize a DnstapHandlerError::Timeout.
    assert_eq!(
        deserialize_dnstap_handler_error(b"dnstap-replay/DnstapHandlerError\x00\x00\x00\x00\x02")
            .unwrap(),
        DnstapHandlerError::Timeout
    );

    // The only way to serialize a DnstapHandlerError::MissingField.
    assert_eq!(
        deserialize_dnstap_handler_error(b"dnstap-replay/DnstapHandlerError\x00\x00\x00\x00\x03")
            .unwrap(),
        DnstapHandlerError::MissingField
    );
}

pub fn fmt_dns_message(s: &mut String, prefix: &str, raw_msg_bytes: &[u8]) {
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

        if let Some(optrec) = msg.opt() {
            s.push_str("\n;; OPT PSEUDOSECTION:\n");
            s.push_str(prefix);
            s.push_str("; EDNS: version ");
            s.push_str(&optrec.version().to_string());
            s.push_str("; flags: ");
            if optrec.dnssec_ok() {
                s.push_str("do ");
            }
            s.push_str("; udp: ");
            s.push_str(&optrec.udp_payload_size().to_string());
            s.push('\n');

            for opt in optrec.iter::<AllOptData<_>>().flatten() {
                match opt {
                    AllOptData::Nsid(nsid) => {
                        s.push_str("; NSID: ");
                        s.push_str(&nsid.to_string());
                        if let Ok(nsid_data) = hex::decode(&nsid.to_string()) {
                            if let Ok(nsid_str) = std::str::from_utf8(&nsid_data) {
                                s.push_str(" (\"");
                                s.push_str(nsid_str);
                                s.push_str("\")");
                            }
                        }
                        s.push('\n');
                    }
                    AllOptData::Dau(data) => {
                        s.push_str("; DAU:");
                        for alg in &data {
                            s.push(' ');
                            s.push_str(&alg.to_string());
                        }
                        s.push('\n');
                    }
                    AllOptData::Dhu(data) => {
                        s.push_str("; DHU:");
                        for alg in &data {
                            s.push(' ');
                            s.push_str(&alg.to_string());
                        }
                        s.push('\n');
                    }
                    AllOptData::N3u(data) => {
                        s.push_str("; N3U:");
                        for alg in &data {
                            s.push(' ');
                            s.push_str(&alg.to_string());
                        }
                        s.push('\n');
                    }
                    AllOptData::Expire(expire) => {
                        s.push_str("; EXPIRE: ");
                        if let Some(expire_data) = expire.expire() {
                            s.push_str(&expire_data.to_string());
                            s.push_str(" seconds");
                        }
                        s.push('\n');
                    }
                    AllOptData::TcpKeepalive(data) => {
                        s.push_str("; TCP-KEEPALIVE: ");
                        let iseconds = data.timeout() / 10;
                        let fseconds = data.timeout() % 10;
                        s.push_str(&iseconds.to_string());
                        s.push('.');
                        s.push_str(&fseconds.to_string());
                        s.push_str(" seconds\n");
                    }
                    AllOptData::Padding(padding) => {
                        s.push_str("; PADDING: [");
                        s.push_str(&padding.len().to_string());
                        s.push_str(" bytes]\n");
                    }
                    AllOptData::ClientSubnet(subnet) => {
                        s.push_str("; CLIENT-SUBNET: ");
                        s.push_str("\n;  NETWORK ADDRESS: ");
                        s.push_str(&subnet.addr().to_string());
                        s.push_str("\n;  SOURCE PREFIX-LENGTH: ");
                        s.push_str(&subnet.source_prefix_len().to_string());
                        s.push_str("\n;  SCOPE PREFIX-LENGTH: ");
                        s.push_str(&subnet.scope_prefix_len().to_string());
                        s.push('\n');
                    }
                    AllOptData::Cookie(data) => {
                        s.push_str("; COOKIE: ");
                        s.push_str(&hex::encode(data.cookie()));
                        s.push('\n');
                    }
                    AllOptData::Chain(data) => {
                        s.push_str("; CHAIN: ");
                        s.push_str(&data.start().to_string());
                        s.push('\n');
                    }
                    AllOptData::KeyTag(data) => {
                        s.push_str("; KEY-TAG:");
                        for keytag in &data {
                            s.push(' ');
                            s.push_str(&keytag.to_string());
                        }
                        s.push('\n');
                    }
                    AllOptData::ExtendedError(data) => {
                        s.push_str("; EXTENDED-DNS-ERROR:\n");
                        s.push_str(";  INFO-CODE: (");
                        s.push_str(&data.code().to_int().to_string());
                        s.push_str(") ");
                        s.push_str(&data.code().to_string());
                        s.push('\n');
                        if let Some(text) = data.text() {
                            if let Ok(text_str) = std::str::from_utf8(text) {
                                s.push_str(";  EXTRA-TEXT: \"");
                                s.push_str(text_str);
                                s.push_str("\"\n");
                            }
                        }
                    }
                    AllOptData::Other(data) => {
                        s.push_str("; OPT=");
                        s.push_str(&data.code().to_int().to_string());
                        s.push(':');
                        s.push_str(&hex::encode(data.data()).to_uppercase());
                        s.push('\n');
                    }
                    _ => {
                        s.push_str("; Other unknown EDNS option, giving up.\n");
                    }
                }
            }
        }
    }
}

pub fn dns_message_is_truncated(raw_msg_bytes: &[u8]) -> bool {
    // Only check a message if the complete header (12 octets) was received.
    if raw_msg_bytes.len() >= 12 {
        let msg = domain::base::Header::for_message_slice(raw_msg_bytes);
        return msg.tc();
    }
    false
}

#[test]
fn test_dns_message_is_truncated() {
    // Too few bytes to be a complete DNS header.
    assert!(!dns_message_is_truncated(&hex::decode("1234").unwrap()));

    // Real DNS header with the TC bit set.
    assert!(dns_message_is_truncated(
        &hex::decode("b84587000001000000000001").unwrap()
    ));

    // Real DNS header with the TC bit unset.
    assert!(!dns_message_is_truncated(
        &hex::decode("b84585000001000000010001").unwrap()
    ));
}
