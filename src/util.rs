use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
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

#[derive(Error, Debug)]
pub enum DnstapHandlerError {
    #[error("Mismatch between logged dnstap response and re-queried DNS response, expecting {1} but received {2}")]
    Mismatch(Bytes, String, String),

    #[error("Timeout sending DNS query")]
    Timeout,

    #[error("dnstap payload is missing a required field")]
    MissingField,
}

impl DnstapHandlerError {
    pub fn serialize(&self) -> Bytes {
        let prefix = b"dnstap-replay/DnstapHandlerError\x00";
        match self {
            DnstapHandlerError::Mismatch(mismatch, _, _) => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4 + mismatch.len());
                b.extend_from_slice(prefix);
                b.put_u32(1);
                b.extend_from_slice(mismatch);
                b
            }
            DnstapHandlerError::Timeout => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4);
                b.extend_from_slice(prefix);
                b.put_u32(2);
                b
            }
            DnstapHandlerError::MissingField => {
                let mut b = BytesMut::with_capacity(prefix.len() + 4);
                b.extend_from_slice(prefix);
                b.put_u32(3);
                b
            }
        }
        .freeze()
    }
}
