use thiserror::Error;

const MAX_PAYLOAD_SIZE: usize = 1 << 20;

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("insufficient data: expected at least {0} bytes, got {1}")]
    InsufficientData(usize, usize),
    #[error("invalid opcode: {0}")]
    InvalidOpcode(u8),
    #[error("payload too large: {0} bytes exceeds maximum of {1} bytes")]
    PayloadTooLarge(usize, usize),
}

/// Represents a parsed WebSocket frame per RFC 6455 Section 5.
#[derive(Debug, Clone)]
pub struct WsFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub is_masked: bool,
    pub mask_key: Option<[u8; 4]>,
}

/// Parses a raw WebSocket frame buffer according to RFC 6455 Section 5.
///
/// Returns `WsFrame` on success, or a `FrameError` on failure.
pub fn parse_frame(buf: &[u8]) -> Result<WsFrame, FrameError> {
    if buf.len() < 2 {
        return Err(FrameError::InsufficientData(2, buf.len()));
    }

    let opcode = buf[0] & 0x0F;
    if opcode != 0x01 && opcode != 0x02 && opcode != 0x08 && opcode != 0x09 && opcode != 0x0A {
        return Err(FrameError::InvalidOpcode(opcode));
    }

    let masked = (buf[1] & 0x80) != 0;
    let mut payload_len = (buf[1] & 0x7F) as usize;
    let mut offset = 2usize;

    if payload_len == 126 {
        if buf.len() < offset + 2 {
            return Err(FrameError::InsufficientData(offset + 2, buf.len()));
        }
        payload_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
    } else if payload_len == 127 {
        if buf.len() < offset + 8 {
            return Err(FrameError::InsufficientData(offset + 8, buf.len()));
        }
        let raw: [u8; 8] = buf[offset..offset + 8].try_into().unwrap();
        payload_len = u64::from_be_bytes(raw) as usize;
        offset += 8;
    }

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let mask_key: Option<[u8; 4]> = if masked {
        if buf.len() < offset + 4 {
            return Err(FrameError::InsufficientData(offset + 4, buf.len()));
        }
        let key: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        offset += 4;
        Some(key)
    } else {
        None
    };

    if buf.len() < offset + payload_len {
        return Err(FrameError::InsufficientData(offset + payload_len, buf.len()));
    }

    let mut payload = buf[offset..offset + payload_len].to_vec();
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }

    Ok(WsFrame {
        opcode,
        payload,
        is_masked: masked,
        mask_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_small_unmasked_text_frame() {
        let data = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let frame = parse_frame(&data).unwrap();
        assert_eq!(frame.opcode, 0x01);
        assert!(!frame.is_masked);
        assert!(frame.mask_key.is_none());
        assert_eq!(frame.payload, b"Hello");
    }

    #[test]
    fn test_parse_masked_text_frame() {
        let mask: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
        let plain = b"Hello";
        let mut masked_payload = Vec::with_capacity(plain.len());
        for (i, b) in plain.iter().enumerate() {
            masked_payload.push(b ^ mask[i % 4]);
        }
        let mut data = vec![0x81, 0x85];
        data.extend_from_slice(&mask);
        data.extend_from_slice(&masked_payload);
        let frame = parse_frame(&data).unwrap();
        assert_eq!(frame.opcode, 0x01);
        assert!(frame.is_masked);
        assert_eq!(frame.mask_key, Some(mask));
        assert_eq!(frame.payload, b"Hello");
    }

    #[test]
    fn test_parse_16bit_length() {
        let mut data = vec![0x82, 0x7E, 0x01, 0x00];
        data.extend(vec![0x42u8; 256]);
        let frame = parse_frame(&data).unwrap();
        assert_eq!(frame.opcode, 0x02);
        assert_eq!(frame.payload.len(), 256);
    }

    #[test]
    fn test_insufficient_data() {
        assert!(matches!(
            parse_frame(&[0x81]),
            Err(FrameError::InsufficientData(_, _))
        ));
    }

    #[test]
    fn test_invalid_opcode() {
        assert!(matches!(
            parse_frame(&[0x80, 0x00]),
            Err(FrameError::InvalidOpcode(0x00))
        ));
    }

    #[test]
    fn test_payload_too_large() {
        let mut data = vec![0x82, 0x7F];
        data.extend_from_slice(&(MAX_PAYLOAD_SIZE as u64 + 1).to_be_bytes());
        data.extend(vec![0x00u8; 64]);
        assert!(matches!(
            parse_frame(&data),
            Err(FrameError::PayloadTooLarge(_, _))
        ));
    }

    #[test]
    fn test_close_frame() {
        let data = vec![0x88, 0x02, 0x03, 0xE8];
        let frame = parse_frame(&data).unwrap();
        assert_eq!(frame.opcode, 0x08);
        assert_eq!(frame.payload, vec![0x03, 0xE8]);
    }
}
