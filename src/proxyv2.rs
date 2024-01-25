// Copyright 2021-2024 Fastly, Inc.

use anyhow::{bail, Result};
use bytes::{BufMut, BytesMut};
use log::*;
use std::net::IpAddr;

use crate::{dnstap, util::DnstapHandlerError};

#[derive(Debug)]
pub struct Timespec {
    pub seconds: u64,
    pub nanoseconds: u32,
}

pub fn add_proxy_payload(
    buf: &mut BytesMut,
    msg: &dnstap::Message,
    query_address: &IpAddr,
    timespec: Option<Timespec>,
) -> Result<()> {
    // Codepoint in the range between `PP2_TYPE_MIN_CUSTOM` (0xE0) and `PP2_TYPE_MAX_CUSTOM`
    // (0xEF). This range is "reserved for application-specific data and will never be used by the
    // PROXY Protocol."
    const PP2_TYPE_CUSTOM_TIMESPEC: u8 = 0xEA;

    // u8 `type` (1 byte)
    // u8 `length_hi` (1 byte)
    // u8 `length_lo` (1 byte)
    // u64 `query_time_sec` (8 bytes)
    // u32 `query_time_nsec` (4 bytes)
    const PP2_CUSTOM_TIMESPEC_SIZE: u16 = 3 + 8 + 4;

    // Calculate the number of bytes following the address block needed for the following TLV(s).
    // This is zero if the timespec TLV is not going to be written into the PROXY v2 payload.
    let needed_tlv_size = if timespec.is_some() {
        PP2_CUSTOM_TIMESPEC_SIZE
    } else {
        0
    };

    // Extract the `query_port` field.
    let query_port = match &msg.query_port {
        Some(port) => *port as u16,
        None => bail!(DnstapHandlerError::MissingField),
    };

    // Add the PROXY v2 signature.
    buf.put(&b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"[..]);

    // Add the PROXY version (2) and command (1), PROXY.
    buf.put_u8(0x21);

    // Add the PROXY v2 address block.
    match query_address {
        IpAddr::V4(addr) => {
            // UDP-over-IPv4: protocol constant 0x12.
            buf.put_u8(0x12);

            // Size of the UDP-over-IPv4 address block: 12 bytes. There are two IPv4 addresses
            // (4 bytes each) and two UDP port numbers (2 bytes each).
            //
            // Also add the size of the TLV(s) after the address block.
            buf.put_u16(12 + needed_tlv_size);

            // Original IPv4 source address.
            buf.put_slice(&addr.octets());

            // Original IPv4 destination address. Use 0.0.0.0 since it doesn't matter and the
            // dnstap message payload may not have it.
            buf.put_u32(0);
        }
        IpAddr::V6(addr) => {
            // UDP-over-IPv6: protocol constant 0x22.
            buf.put_u8(0x22);

            // Size of the UDP-over-IPv6 address block: 36 bytes. There are two IPv6 addresses
            // (16 bytes each) and two UDP port numbers (2 bytes each).
            //
            // Also add the size of the TLV(s) after the address block.
            buf.put_u16(36 + needed_tlv_size);

            // Original IPv6 source address.
            buf.put_slice(&addr.octets());

            // Original IPv6 destination address. Use :: since it doesn't matter and the dnstap
            // message payload may not have it.
            buf.put_u128(0);
        }
    };

    // Original UDP source port.
    buf.put_u16(query_port);

    // Original UDP destination port. Use 53 since it doesn't matter and the dnstap message
    // payload may not have it.
    buf.put_u16(53);

    if let Some(timespec) = timespec {
        trace!("Sending PROXY v2 custom TLV: {timespec:?}");

        // Timespec TLV: type field.
        buf.put_u8(PP2_TYPE_CUSTOM_TIMESPEC);

        // Timespec TLV: length field. This is split into a "high byte" and "low byte". The length is
        // of the following value (8 bytes u64 + 4 bytes u32).
        buf.put_u8(0);
        buf.put_u8(12);

        // Timespec TLV: value field. Intentionally encode using little endian byte order.
        buf.put_u64_le(timespec.seconds);
        buf.put_u32_le(timespec.nanoseconds);
    }

    Ok(())
}
