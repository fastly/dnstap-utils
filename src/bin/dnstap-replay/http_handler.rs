// Copyright 2021-2022 Fastly, Inc.

use anyhow::Result;
use async_channel::Receiver;
use async_stream::stream;
use bytes::{BufMut, BytesMut};
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use hyper::{Method, StatusCode};
use log::*;
use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::Encoder as PrometheusEncoder;
use prometheus::TextEncoder;
use prost::Message;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio_util::codec::Encoder as CodecEncoder;

use dnstap_utils::dnstap;
use dnstap_utils::framestreams_codec::{self, Frame, FrameStreamsCodec};

use crate::Channels;

/// Process HTTP requests.
pub struct HttpHandler {
    /// HTTP server socket to listen on.
    http_address: SocketAddr,

    /// Server channels.
    channels: Channels,
}

/// Structure for encapsulating a channel together with the metric to be incremented when a payload
/// is successfully read from the channel. Used below by the HTTP endpoints that read from the
/// error and timeout channels.
struct HttpChannel {
    receiver: Receiver<dnstap::Dnstap>,
    success_metric: &'static GenericCounter<AtomicU64>,
}

impl HttpHandler {
    /// Create a new [`HttpHandler`] that listens on `http_address`. For the `/errors`
    /// endpoint, error dnstap payloads will be retrieved from `channel_error_receiver`.
    pub fn new(http_address: SocketAddr, channels: &Channels) -> Self {
        HttpHandler {
            http_address,
            channels: channels.clone(),
        }
    }

    /// Run the HTTP server.
    pub async fn run(&self) -> Result<()> {
        // Clone the channels for the outer closure.
        let channel_error = self.channels.error_receiver.clone();
        let channel_timeout = self.channels.timeout_receiver.clone();

        let make_svc = make_service_fn(move |_| {
            // Clone the channels again for the inner closure.
            let channel_error = channel_error.clone();
            let channel_timeout = channel_timeout.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let channel_error = HttpChannel {
                        receiver: channel_error.clone(),
                        success_metric: &crate::metrics::CHANNEL_ERROR_RX.success,
                    };
                    let channel_timeout = HttpChannel {
                        receiver: channel_timeout.clone(),
                        success_metric: &crate::metrics::CHANNEL_TIMEOUT_RX.success,
                    };

                    async move { http_service(req, channel_error, channel_timeout).await }
                }))
            }
        });

        // Bind to the HTTP server address.
        let server = hyper::server::Server::try_bind(&self.http_address)?.serve(make_svc);
        info!("HTTP server listening on http://{}", &self.http_address);

        Ok(server.await?)
    }
}

/// Route HTTP requests based on method/path.
async fn http_service(
    req: Request<Body>,
    channel_error: HttpChannel,
    channel_timeout: HttpChannel,
) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        // Handle the `/metrics` endpoint.
        (&Method::GET, "/metrics") => get_metrics_response(),

        // Handle the `/errors` endpoint.
        (&Method::GET, "/errors") => get_channel_response(channel_error),

        // Handle the `/timeouts` endpoint.
        (&Method::GET, "/timeouts") => get_channel_response(channel_timeout),

        // Default 404 Not Found response.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

/// Handle requests for the Prometheus metrics endpoint.
fn get_metrics_response() -> Result<Response<Body>> {
    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();

    Ok(response)
}

/// Handle requests for the endpoints that return a Frame Streams formatted log file of dnstap
/// payloads from a channel.
fn get_channel_response(channel: HttpChannel) -> Result<Response<Body>> {
    Ok(Response::new(Body::wrap_stream(dnstap_receiver_to_stream(
        channel,
    ))))
}

/// Read dnstap payloads from the [`async_channel::Receiver`] embedded in an `HttpChannel`,
/// serialize them using the unidirectional Frame Streams encoding, and yield them to a
/// [`tokio_stream::Stream`]. Increments the success counter contained in the `HttpChannel`.
fn dnstap_receiver_to_stream(
    channel: HttpChannel,
) -> impl tokio_stream::Stream<Item = std::result::Result<BytesMut, std::io::Error>> {
    let mut f = FrameStreamsCodec {};

    stream! {
        // Write the Start frame with the dnstap content type to the beginning of the stream.
        let mut buf = BytesMut::with_capacity(64);
        f.encode(
            Frame::ControlStart(framestreams_codec::encode_content_type_payload(
                b"protobuf:dnstap.Dnstap",
            )),
            &mut buf,
        )?;
        yield Ok(buf);

        // Get each dnstap payload from the channel and write it to the stream.
        loop {
            match channel.receiver.try_recv() {
                Ok(d) => {
                    // Accounting.
                    channel.success_metric.inc();

                    // Get the length of the serialized protobuf.
                    let len = d.encoded_len();

                    // Create a [`BytesMut`] of the exact size needed for this data frame.
                    let mut buf = BytesMut::with_capacity(4 + len);

                    // Write the length of the protobuf to the beginning of the data frame.
                    buf.put_u32(len as u32);

                    // Serialize the protobuf and write it to the data frame.
                    d.encode(&mut buf).unwrap();

                    yield Ok(buf);
                }
                Err(_) => {
                    // Write the Stop frame to the end of the stream.
                    let mut buf = BytesMut::with_capacity(64);
                    f.encode(Frame::ControlStop, &mut buf)?;
                    yield Ok(buf);

                    // No more frames.
                    break;
                }
            }
        }
    }
}
