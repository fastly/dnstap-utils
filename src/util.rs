use anyhow::{bail, Result};
use std::convert::TryFrom;
use std::net::IpAddr;

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
