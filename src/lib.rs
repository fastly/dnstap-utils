pub mod dnstap {
    #![allow(clippy::module_inception)]
    #![allow(rustdoc::bare_urls)]
    include!(concat!(env!("OUT_DIR"), "/dnstap.rs"));
}
