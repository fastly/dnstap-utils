// Copyright 2021 Fastly, Inc.

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

// Implementation defined limits.

pub const CONTROL_FRAME_LENGTH_MAX: usize = 512;
pub const FRAME_LENGTH_MAX: usize = 128 * 1024;

// Protocol constants.

pub const FRAMESTREAMS_CONTROL_ACCEPT: u32 = 0x01;
pub const FRAMESTREAMS_CONTROL_START: u32 = 0x02;
pub const FRAMESTREAMS_CONTROL_STOP: u32 = 0x03;
pub const FRAMESTREAMS_CONTROL_READY: u32 = 0x04;
pub const FRAMESTREAMS_CONTROL_FINISH: u32 = 0x05;

pub const FRAMESTREAMS_CONTROL_FIELD_CONTENT_TYPE: u32 = 0x01;

pub const FRAMESTREAMS_ESCAPE_SEQUENCE: u32 = 0x00;

#[derive(Debug)]
pub enum Frame {
    ControlReady(BytesMut),
    ControlAccept(BytesMut),
    ControlStart(BytesMut),
    ControlStop,
    ControlFinish,
    ControlUnknown(BytesMut),
    Data(BytesMut),
}

pub struct FrameStreamsCodec {}

impl Encoder<Frame> for FrameStreamsCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match frame {
            Frame::ControlReady(payload) => {
                dst.put_u32(FRAMESTREAMS_ESCAPE_SEQUENCE);
                dst.put_u32(4);
                dst.put_u32(FRAMESTREAMS_CONTROL_READY);
                dst.put(payload);
            }
            Frame::ControlAccept(payload) => {
                dst.put_u32(FRAMESTREAMS_ESCAPE_SEQUENCE);
                dst.put_u32(4 + payload.len() as u32);
                dst.put_u32(FRAMESTREAMS_CONTROL_ACCEPT);
                dst.put(payload);
            }
            Frame::ControlStart(payload) => {
                dst.put_u32(FRAMESTREAMS_ESCAPE_SEQUENCE);
                dst.put_u32(4 + payload.len() as u32);
                dst.put_u32(FRAMESTREAMS_CONTROL_START);
                dst.put(payload);
            }
            Frame::ControlStop => {
                dst.put_u32(FRAMESTREAMS_ESCAPE_SEQUENCE);
                dst.put_u32(4);
                dst.put_u32(FRAMESTREAMS_CONTROL_STOP);
            }
            Frame::ControlFinish => {
                dst.put_u32(FRAMESTREAMS_ESCAPE_SEQUENCE);
                dst.put_u32(4);
                dst.put_u32(FRAMESTREAMS_CONTROL_FINISH);
            }
            Frame::ControlUnknown(_) => todo!(),
            Frame::Data(payload) => {
                dst.put_u32(payload.len() as u32);
                dst.put(payload);
            }
        }
        Ok(())
    }
}

impl Decoder for FrameStreamsCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Check if there is enough data to read the frame length.
        if src.len() < 4 {
            return Ok(None);
        }

        // Read the frame length.
        let mut len_frame_bytes = [0u8; 4];
        len_frame_bytes.copy_from_slice(&src[..4]);
        let len_frame = u32::from_be_bytes(len_frame_bytes) as usize;

        // Enforce the maximum frame size.
        if len_frame > FRAME_LENGTH_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Frame of length {} is too large for this implementation",
                    len_frame
                ),
            ));
        }

        // Check if this is a control frame.
        if len_frame == FRAMESTREAMS_ESCAPE_SEQUENCE as usize {
            // Check if there is enough data to read the control frame escape (4 bytes) + the
            // control frame length (4 bytes).
            if src.len() < 4 + 4 {
                return Ok(None);
            }

            // Read the control frame length.
            let mut len_control_bytes = [0u8; 4];
            len_control_bytes.copy_from_slice(&src[4..8]);
            let len_control = u32::from_be_bytes(len_control_bytes) as usize;

            // Check that the control frame length is large enough. The minimum control frame
            // length is 4 bytes (to encode the control frame types that have no payload).
            if len_control < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Control frame of length {} is too small", len_control),
                ));
            }

            // Check that the control frame length is not too large.
            if len_control > CONTROL_FRAME_LENGTH_MAX {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Control frame of length {} is too large", len_control),
                ));
            }

            // Check if there is enough data to read the full control frame sequence of the control
            // frame escape (4 bytes) + the control frame length (4 bytes) + the actual length of
            // the control frame.
            if src.len() < 4 + 4 + len_control {
                return Ok(None);
            }

            // Detach the control frame escape (4 bytes) and the control frame length (4 bytes).
            src.advance(4 + 4);

            // Read the control frame type. This is the first 4 bytes of the control frame.
            let control_frame_type = src.get_u32();

            // Detach the control frame payload. This is the remainder of the control frame after
            // the control frame type.
            let payload = src.split_to(len_control - 4);

            Ok(Some(match control_frame_type {
                FRAMESTREAMS_CONTROL_READY => Frame::ControlReady(payload),
                FRAMESTREAMS_CONTROL_ACCEPT => Frame::ControlAccept(payload),
                FRAMESTREAMS_CONTROL_START => Frame::ControlStart(payload),
                FRAMESTREAMS_CONTROL_STOP => Frame::ControlStop,
                FRAMESTREAMS_CONTROL_FINISH => Frame::ControlFinish,
                _ => Frame::ControlUnknown(payload),
            }))
        } else {
            // This is a data frame.

            // Check if there is enough data to read the frame length plus the data frame.
            if src.len() < 4 + len_frame {
                // Inform the Framed that more data is needed.
                return Ok(None);
            }

            // Detach the frame length.
            src.advance(4);

            // Detach the data frame.
            let data = src.split_to(len_frame);

            // Return the bytes of the frame.
            Ok(Some(Frame::Data(data)))
        }
    }
}

/// Helper function for encoding the "content type" payload used in the Frame Streams Ready,
/// Accept, and Start control frames.
pub fn encode_content_type_payload(content_type: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + 4 + content_type.len());
    buf.put_u32(FRAMESTREAMS_CONTROL_FIELD_CONTENT_TYPE);
    buf.put_u32(content_type.len() as u32);
    buf.put(content_type);
    buf
}
