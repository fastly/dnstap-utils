// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use clap::Parser;
use std::fmt::Debug;
use std::io::Write;

use dnstap_utils::util::fmt_dns_message;

#[derive(Parser, Debug)]
struct Opts {
    /// Hex-encoded DNS message data to decode
    hex_msg_bytes: String,
}

fn main() -> Result<()> {
    let mut opts = Opts::parse();

    // Strip whitespace characters from the command-line input data.
    opts.hex_msg_bytes.retain(|c| !c.is_whitespace());

    // Decode the hex-encoded input data into a binary, wire-format DNS message.
    let raw_msg_bytes = hex::decode(&opts.hex_msg_bytes)?;

    // Format the wire-format DNS message to a string.
    let mut fmt_buffer = String::with_capacity(2048);
    fmt_dns_message(&mut fmt_buffer, "", &raw_msg_bytes);

    // Write the formatted DNS message to stdout.
    std::io::stdout().write_all(fmt_buffer.as_bytes())?;

    Ok(())
}
