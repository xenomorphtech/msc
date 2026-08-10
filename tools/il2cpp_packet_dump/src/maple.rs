use std::sync::OnceLock;

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAPLE_AES_KEY: [u8; 32] = [
    0x29, 0, 0, 0, 0xe1, 0, 0, 0, 0x52, 0, 0, 0, 0xf1, 0, 0, 0, 0xb3, 0, 0, 0, 0x87, 0, 0, 0, 0x24,
    0, 0, 0, 0x06, 0, 0, 0,
];
const FIRST_AES_CHUNK: usize = 0x5b0;
const FOLLOWING_AES_CHUNK: usize = 0x5b4;
const IV_SHUFFLE_HEX: &str = concat!(
    "ec3f77a445d071bfb79820fc4be9b3e15c22f70c441b81bd638dd4c3f21019e",
    "0fba16e66eaaed6ce06184eeb7895dbbab6427a2a830b54676de865e72f07f3aa",
    "277b85b026fd8ba9fabea8d7cbcc92daf993602dddd2a29b395f82214c69f831",
    "87ee8ead8c6abcb56b5913f10400f65a3579488f15cd9757123e37ff9d4f51f5",
    "a370bb1475c2b872c0ed7d68c92e0d624617114d6cc47e53c125c79a1c88582c",
    "89dc026440015d38a5e2af55d5ef1a7ca75ba66f869f73e60ade2b994a479cdf",
    "09769e300ee4b294a03b341d280f36e323b403d890c83cfe5e3224501f3a438a",
    "964174ac5233f0d92980b116d3ab91b9847f611ecfc5d1563dcaf405c6e50849"
);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Handshake {
    pub packet_length: u16,
    pub version: u16,
    pub subversion: String,
    pub first_iv: [u8; 4],
    pub second_iv: [u8; 4],
    pub locale: u8,
    pub trailing_hex: String,
}

impl Handshake {
    #[must_use]
    pub const fn wire_length(&self) -> usize {
        self.packet_length as usize + 2
    }
}

#[derive(Clone, Debug)]
pub struct DecryptedDirection {
    pub version_mask: u16,
    pub plaintexts: Vec<Vec<u8>>,
}

/// Parse the server's unencrypted Maple handshake.
///
/// # Errors
///
/// Returns an error for truncated fields or invalid UTF-16.
pub fn parse_handshake(data: &[u8]) -> Result<Handshake> {
    if data.len() < 6 {
        bail!("handshake is shorter than its fixed fields");
    }
    let packet_length = u16::from_le_bytes([data[0], data[1]]);
    let version = u16::from_le_bytes([data[2], data[3]]);
    let subversion_length = usize::from(u16::from_le_bytes([data[4], data[5]]));
    let wire_length = usize::from(packet_length) + 2;
    if data.len() < wire_length {
        bail!(
            "handshake declares {wire_length} wire bytes, only {} are present",
            data.len()
        );
    }
    let mut cursor = 6_usize;
    let subversion_bytes = subversion_length.saturating_mul(2);
    if cursor.saturating_add(subversion_bytes).saturating_add(9) > wire_length {
        bail!("handshake subversion extends beyond the packet");
    }
    let utf16 = data[cursor..cursor + subversion_bytes]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let subversion = String::from_utf16(&utf16)?;
    cursor += subversion_bytes;
    let first_iv = data[cursor..cursor + 4].try_into()?;
    let second_iv = data[cursor + 4..cursor + 8].try_into()?;
    let locale = data[cursor + 8];
    cursor += 9;
    Ok(Handshake {
        packet_length,
        version,
        subversion,
        first_iv,
        second_iv,
        locale,
        trailing_hex: hex::encode(&data[cursor..wire_length]),
    })
}

#[must_use]
pub fn decode_frame_length(header: &[u8; 4]) -> usize {
    usize::from(
        u16::from_le_bytes([header[0], header[1]]) ^ u16::from_le_bytes([header[2], header[3]]),
    )
}

/// Encode the four-byte Maple frame header for one cipher direction.
///
/// # Errors
///
/// Returns an error when the payload cannot fit in the protocol's `u16` length.
pub fn encode_frame_header(
    payload_length: usize,
    iv: [u8; 4],
    version_mask: u16,
) -> Result<[u8; 4]> {
    let payload_length = u16::try_from(payload_length)
        .context("Maple encrypted frame payload exceeds 65535 bytes")?;
    let first_word = u16::from_le_bytes([iv[2], iv[3]]) ^ version_mask;
    let second_word = first_word ^ payload_length;
    let first = first_word.to_le_bytes();
    let second = second_word.to_le_bytes();
    Ok([first[0], first[1], second[0], second[1]])
}

/// Validate and decrypt all frames in one directional byte stream.
///
/// # Errors
///
/// Returns an error for truncated frames or an IV/version-header mismatch.
pub fn decrypt_direction(data: &[u8], initial_iv: [u8; 4]) -> Result<DecryptedDirection> {
    if data.is_empty() {
        return Ok(DecryptedDirection {
            version_mask: 0,
            plaintexts: Vec::new(),
        });
    }
    if data.len() < 4 {
        bail!("encrypted stream ends inside its first frame header");
    }
    let first_word = u16::from_le_bytes([data[0], data[1]]);
    let version_mask = first_word ^ u16::from_le_bytes([initial_iv[2], initial_iv[3]]);
    let mut iv = initial_iv;
    let mut offset = 0_usize;
    let mut plaintexts = Vec::new();
    while offset < data.len() {
        if data.len() - offset < 4 {
            bail!(
                "encrypted stream has {} trailing header bytes",
                data.len() - offset
            );
        }
        let header: [u8; 4] = data[offset..offset + 4].try_into()?;
        let payload_length = decode_frame_length(&header);
        let end = offset.saturating_add(4).saturating_add(payload_length);
        if end > data.len() {
            bail!(
                "encrypted frame {} declares {payload_length} bytes, only {} remain",
                plaintexts.len(),
                data.len() - offset - 4
            );
        }
        let expected = encode_frame_header(payload_length, iv, version_mask)?;
        if header != expected {
            bail!(
                "encrypted frame {} header is inconsistent with its directional IV/version mask",
                plaintexts.len()
            );
        }
        plaintexts.push(crypt_payload(&data[offset + 4..end], iv));
        iv = shuffle_iv(iv);
        offset = end;
    }
    Ok(DecryptedDirection {
        version_mask,
        plaintexts,
    })
}

#[must_use]
pub fn crypt_payload(payload: &[u8], iv: [u8; 4]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(&MAPLE_AES_KEY));
    let mut transformed = payload.to_vec();
    let mut offset = 0_usize;
    let mut chunk_length = FIRST_AES_CHUNK;
    while offset < transformed.len() {
        let segment_end = offset.saturating_add(chunk_length).min(transformed.len());
        let mut keystream = [0_u8; 16];
        for chunk in keystream.chunks_exact_mut(4) {
            chunk.copy_from_slice(&iv);
        }
        let mut cursor = offset;
        while cursor < segment_end {
            let mut block = GenericArray::clone_from_slice(&keystream);
            cipher.encrypt_block(&mut block);
            keystream.copy_from_slice(&block);
            let block_end = cursor.saturating_add(16).min(segment_end);
            for index in 0..block_end - cursor {
                transformed[cursor + index] ^= keystream[index];
            }
            cursor = block_end;
        }
        offset = segment_end;
        chunk_length = FOLLOWING_AES_CHUNK;
    }
    transformed
}

#[must_use]
pub fn shuffle_iv(iv: [u8; 4]) -> [u8; 4] {
    let table = iv_shuffle();
    let mut shuffled = [0xf2_u8, 0x53, 0x50, 0xc6];
    for value in iv {
        shuffled[0] = shuffled[0]
            .wrapping_add(table[usize::from(shuffled[1])])
            .wrapping_sub(value);
        shuffled[1] = shuffled[1].wrapping_sub(shuffled[2] ^ table[usize::from(value)]);
        shuffled[2] ^= table[usize::from(shuffled[3])].wrapping_add(value);
        shuffled[3] = shuffled[3].wrapping_sub(shuffled[0].wrapping_sub(table[usize::from(value)]));
        shuffled = u32::from_le_bytes(shuffled).rotate_left(3).to_le_bytes();
    }
    shuffled
}

fn iv_shuffle() -> &'static [u8; 256] {
    static TABLE: OnceLock<[u8; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        hex::decode(IV_SHUFFLE_HEX)
            .expect("embedded IV table is valid hex")
            .try_into()
            .expect("embedded IV table has 256 bytes")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_iv_shuffle_vector_matches_reference() {
        let first = shuffle_iv([0x6e, 0x3c, 0x79, 0x5a]);
        assert_eq!(first, [0x25, 0x95, 0x49, 0x10]);
        assert_eq!(shuffle_iv(first), [0x0a, 0xbd, 0xbb, 0xa5]);
    }

    #[test]
    fn aes_operation_is_symmetric() {
        let iv = [1, 2, 3, 4];
        let plaintext = (0_u8..=255).cycle().take(3000).collect::<Vec<_>>();
        let ciphertext = crypt_payload(&plaintext, iv);
        assert_ne!(ciphertext, plaintext);
        assert_eq!(crypt_payload(&ciphertext, iv), plaintext);
    }

    #[test]
    fn frame_header_rejects_oversized_payload() {
        assert!(encode_frame_header(65_536, [0; 4], 3).is_err());
    }
}
