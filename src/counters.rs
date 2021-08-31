use once_cell::sync::Lazy;
use prometheus::{opts, register_int_counter, register_int_counter_vec};
use prometheus::{IntCounter, IntCounterVec};

pub static DATA_FRAMES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "data_frames_total",
        "Number of Frame Streams data frames processed."
    ))
    .unwrap()
});

pub static DATA_BYTES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!(
        "data_bytes_total",
        "Number of Frame Streams data frame bytes processed."
    ))
    .unwrap()
});

pub static DNS_COMPARISONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "dns_comparisons_total",
        "Number of DNS comparison operations performed.",
        &["result"]
    )
    .unwrap()
});

pub static DNS_QUERIES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "dns_queries_total",
        "Number of DNS re-query operations performed.",
        &["result"]
    )
    .unwrap()
});
