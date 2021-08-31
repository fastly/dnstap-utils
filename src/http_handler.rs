// Copyright 2021 Fastly, Inc.

use anyhow::Result;
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use hyper::{Method, StatusCode};
use log::*;
use std::convert::Infallible;
use std::net::SocketAddr;

use prometheus::Encoder;
use prometheus::TextEncoder;

pub struct HttpHandler {
    http_address: SocketAddr,
}

impl HttpHandler {
    pub fn new(http_address: SocketAddr) -> Self {
        HttpHandler { http_address }
    }

    pub async fn run(&mut self) -> Result<()> {
        let make_svc =
            make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(http_service)) });
        let server = hyper::server::Server::try_bind(&self.http_address)?.serve(make_svc);
        info!("HTTP server listening on http://{}", &self.http_address);
        Ok(server.await?)
    }
}

async fn http_service(req: Request<Body>) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => get_prometheus_response(),
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn get_prometheus_response() -> Result<Response<Body>> {
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
