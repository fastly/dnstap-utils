// Copyright 2021 Fastly, Inc.

use anyhow::bail;
use anyhow::Result;
use futures::SinkExt;
use log::*;
use prost::Message;
use std::os::unix::io::AsRawFd;
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::dnstap;
use crate::framestreams_codec::{self, Frame, FrameStreamsCodec};

/// Per-connection FrameStreams protocol handler. Reads delimited frames from the Unix socket
/// stream, decodes the protobuf payload, and then sends the protobuf object over a channel to a
/// [`DnstapHandler`] for further processing.
pub struct FrameHandler {
    /// The send side of the async channel, used by [`FrameHandler`]'s to send decoded dnstap
    /// protobuf messages to the [`DnstapHandler`]'s.
    channel_sender: async_channel::Sender<dnstap::Dnstap>,

    /// The Unix stream to read frames from.
    stream: UnixStream,

    /// Identifying description of the connected `stream`.
    stream_descr: String,

    /// Counter of the number of bytes processed by this [`FrameHandler`].
    count_data_bytes: usize,

    /// Counter of the number of frames processed by this [`FrameHandler`].
    count_data_frames: usize,
}

impl FrameHandler {
    /// Create a new [`FrameHandler`] that reads from [`stream`] and writes decoded protobuf
    /// messages to [`channel_sender`].
    pub fn new(stream: UnixStream, channel_sender: async_channel::Sender<dnstap::Dnstap>) -> Self {
        let stream_descr = format!("fd {}", stream.as_raw_fd());

        FrameHandler {
            stream,
            stream_descr,
            channel_sender,
            count_data_bytes: 0,
            count_data_frames: 0,
        }
    }

    /// Set up the FrameStreams connection and processing the incoming data frames.
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Accepted new Frame Streams connection on {}",
            self.stream_descr
        );

        // Initialize the FrameStreams codec.
        let mut framed = Framed::with_capacity(
            &mut self.stream,
            FrameStreamsCodec {},
            framestreams_codec::FRAME_LENGTH_MAX,
        );

        // Process each frame from the connection.
        while let Some(frame) = framed.next().await {
            match frame {
                Ok(frame) => {
                    match frame {
                        Frame::ControlReady(payload) => {
                            // Ready: This is the first control frame received from the sender.
                            // Send the Accept control frame.
                            //
                            // XXX: We mirror the content type(s) specified in the Ready control
                            // frame payload into the Accept control frame payload. Instead we
                            // should select a specific content type from the sender's list.
                            framed.send(Frame::ControlAccept(payload)).await?;
                        }
                        Frame::ControlAccept(_) => {
                            // Accept: This is the control frame that the receiver sends in
                            // response to the Ready frame. It is a protocol violation for a sender
                            // to send an Accept control frame.
                            bail!(
                                "{}: Protocol error: Sender sent ACCEPT frame",
                                self.stream_descr
                            );
                        }
                        Frame::ControlStart(payload) => {
                            // Start: This is the control frame that the sender sends in response
                            // to the Accept frame and indicates it will begin sending data frames
                            // of the type specified in the Start control frame payload.
                            //
                            // XXX: We should probably do something with the content type that the
                            // sender specifies in the Start control frame payload.
                            trace!(
                                "{}: START payload: {}",
                                self.stream_descr,
                                hex::encode(&payload)
                            );
                        }
                        Frame::ControlStop => {
                            // Stop: This is the control frame that the sender sends when it is
                            // done sending Data frames. Send the Finish frame acknowledging
                            // shutdown of the stream.
                            info!(
                                "{}: STOP received, processed {} data frames, {} data bytes",
                                self.stream_descr, self.count_data_frames, self.count_data_bytes,
                            );
                            framed.send(Frame::ControlFinish).await?;

                            // Shut the [`FrameHandler`] down.
                            return Ok(());
                        }
                        Frame::ControlFinish => {
                            // Protocol violation for a receiver to receive a Finish control frame.
                            bail!(
                                "{}: Protocol error: Sender sent FINISH frame",
                                self.stream_descr
                            );
                        }
                        Frame::ControlUnknown(_) => {
                            bail!(
                                "{}: Protocol error: Sender sent unknown control frame",
                                self.stream_descr
                            );
                        }
                        Frame::Data(mut payload) => {
                            // Data: Let's process it.
                            trace!("got a data payload");

                            // Accounting.
                            crate::counters::DATA_FRAMES.inc();
                            crate::counters::DATA_BYTES.inc_by(payload.len() as u64);
                            self.count_data_bytes += payload.len();
                            self.count_data_frames += 1;

                            // Decode the protobuf message.
                            match dnstap::Dnstap::decode(&mut payload) {
                                // The message was successfully parsed, send it to a
                                // [`DnstapHandler`] for further processing.
                                Ok(d) => {
                                    let _ = self.channel_sender.send(d).await;
                                }
                                // The payload failed to parse.
                                Err(e) => {
                                    bail!(
                                        "{}: Protocol error: Decoding dnstap protobuf message: {}, payload: {}",
                                        self.stream_descr,
                                        e,
                                        hex::encode(&payload)
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    bail!("{}: Protocol error: {}", self.stream_descr, e);
                }
            }
        }

        Ok(())
    }
}
