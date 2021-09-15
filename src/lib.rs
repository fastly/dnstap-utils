pub mod dnstap {
    #![allow(clippy::module_inception)]
    include!(concat!(env!("OUT_DIR"), "/dnstap.rs"));
}
