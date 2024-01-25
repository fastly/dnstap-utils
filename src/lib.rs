// Copyright 2021-2024 Fastly, Inc.

pub mod dnstap {
    #![allow(clippy::module_inception)]
    #![allow(rustdoc::bare_urls)]
    include!(concat!(env!("OUT_DIR"), "/dnstap.rs"));
}

pub mod framestreams_codec;

pub mod proxyv2;
pub mod util;
