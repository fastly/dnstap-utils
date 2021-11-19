// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use async_stream::stream;
use bytes::{BufMut, BytesMut};
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use hyper::{Method, StatusCode};
use log::*;
use prometheus::Encoder as PrometheusEncoder;
use prometheus::TextEncoder;
use prost::Message;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio_util::codec::Encoder as CodecEncoder;

use dnstap_utils::dnstap;
use dnstap_utils::framestreams_codec::{self, Frame, FrameStreamsCodec};

/// Process HTTP requests.
pub struct HttpHandler {
    http_address: SocketAddr,
    channel_error_receiver: async_channel::Receiver<dnstap::Dnstap>,
}

impl HttpHandler {
    /// Create a new [`HttpHandler`] that listens on `http_address`. For the `/errors`
    /// endpoint, error dnstap payloads will be retrieved from `channel_error_receiver`.
    pub fn new(
        http_address: SocketAddr,
        channel_error_receiver: async_channel::Receiver<dnstap::Dnstap>,
    ) -> Self {
        HttpHandler {
            http_address,
            channel_error_receiver,
        }
    }

    /// Run the HTTP server.
    pub async fn run(&self) -> Result<()> {
        // Clone the error channel for the outer closure.
        let channel = self.channel_error_receiver.clone();

        let make_svc = make_service_fn(move |_| {
            // Clone the error channel again for the inner closure.
            let channel = channel.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let channel = channel.clone();

                    async move { http_service(req, channel).await }
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
pub async fn http_service(
    req: Request<Body>,
    channel_error_receiver: async_channel::Receiver<dnstap::Dnstap>,
) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        // Handle the `/metrics` endpoint.
        (&Method::GET, "/metrics") => get_metrics_response(),

        // Handle the `/errors` endpoint.
        (&Method::GET, "/errors") => get_errors_response(channel_error_receiver),

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

/// Handle requests for the errors endpoint, which returns a Frame Streams formatted log file
/// of the error dnstap payloads.
fn get_errors_response(
    channel: async_channel::Receiver<dnstap::Dnstap>,
) -> Result<Response<Body>> {
    Ok(Response::new(Body::wrap_stream(dnstap_receiver_to_stream(
        channel,
    ))))
}

/// Read dnstap payloads from an [`async_channel::Receiver`], serialize them using the
/// unidirectional Frame Streams encoding, and yield them to a [`tokio_stream::Stream`].
fn dnstap_receiver_to_stream(
    channel: async_channel::Receiver<dnstap::Dnstap>,
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
            match channel.try_recv() {
                Ok(d) => {
                    // Accounting.
                    crate::metrics::CHANNEL_ERROR_RX
                        .with_label_values(&["success"])
                        .inc();

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
