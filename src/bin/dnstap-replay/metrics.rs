use lazy_static::{initialize, lazy_static};
use prometheus::{opts, register_int_counter, register_int_counter_vec, IntCounter};
use prometheus_static_metric::{make_static_metric, register_static_int_counter_vec};

make_static_metric! {
    pub struct ChannelErrorRxVec: IntCounter {
        "result" => {
            success,
        },
    }

    pub struct ChannelErrorTxVec: IntCounter {
        "result" => {
            success,
            error,
        },
    }

    pub struct DnsComparisonsVec: IntCounter {
        "result" => {
            matched,
            mismatched,
            suppressed,
        },
    }

    pub struct DnsQueriesVec: IntCounter {
        "result" => {
            success,
            error,
            timeout,
        },
    }

    pub struct DnstapPayloadsVec: IntCounter {
        "result" => {
            success,
            error,
        },
    }

    pub struct DnstapHandlerInternalErrorsVec: IntCounter {
        "result" => {
            discard_non_udp,
        },
    }
}

lazy_static! {
    pub static ref CHANNEL_ERROR_RX: ChannelErrorRxVec = register_static_int_counter_vec!(
        ChannelErrorRxVec,
        "dnstap_replay_channel_error_rx_total",
        "Number of error channel receives performed.",
        &["result"]
    )
    .unwrap();
    pub static ref CHANNEL_ERROR_TX: ChannelErrorTxVec = register_static_int_counter_vec!(
        ChannelErrorTxVec,
        "dnstap_replay_channel_error_tx_total",
        "Number of error channel sends performed.",
        &["result"]
    )
    .unwrap();
    pub static ref DATA_BYTES: IntCounter = register_int_counter!(opts!(
        "dnstap_replay_data_bytes_total",
        "Number of Frame Streams data frame bytes processed."
    ))
    .unwrap();
    pub static ref DATA_FRAMES: IntCounter = register_int_counter!(opts!(
        "dnstap_replay_data_frames_total",
        "Number of Frame Streams data frames processed."
    ))
    .unwrap();
    pub static ref DNS_COMPARISONS: DnsComparisonsVec = register_static_int_counter_vec!(
        DnsComparisonsVec,
        "dnstap_replay_dns_comparisons_total",
        "Number of DNS comparison operations performed.",
        &["result"]
    )
    .unwrap();
    pub static ref DNS_QUERIES: DnsQueriesVec = register_static_int_counter_vec!(
        DnsQueriesVec,
        "dnstap_replay_dns_queries_total",
        "Number of DNS re-query operations performed.",
        &["result"]
    )
    .unwrap();
    pub static ref DNSTAP_PAYLOADS: DnstapPayloadsVec = register_static_int_counter_vec!(
        DnstapPayloadsVec,
        "dnstap_replay_dnstap_payloads_total",
        "Number of dnstap payloads processed.",
        &["result"]
    )
    .unwrap();
    pub static ref DNSTAP_HANDLER_INTERNAL_ERRORS: DnstapHandlerInternalErrorsVec =
        register_static_int_counter_vec!(
            DnstapHandlerInternalErrorsVec,
            "dnstap_replay_dnstap_handler_internal_errors_total",
            "Number of internal errors encountered by dnstap handler.",
            &["result"]
        )
        .unwrap();
}

pub fn initialize_metrics() {
    initialize(&CHANNEL_ERROR_RX);
    initialize(&CHANNEL_ERROR_TX);
    initialize(&DATA_BYTES);
    initialize(&DATA_FRAMES);
    initialize(&DNS_COMPARISONS);
    initialize(&DNS_QUERIES);
    initialize(&DNSTAP_PAYLOADS);
    initialize(&DNSTAP_HANDLER_INTERNAL_ERRORS);
}
