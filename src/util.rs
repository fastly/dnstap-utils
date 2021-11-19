use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
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
