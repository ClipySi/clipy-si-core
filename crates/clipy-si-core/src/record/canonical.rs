//! Deterministic length-prefix binary layout for a record's plaintext body.
//!
//! This is the **plaintext** that gets AES-GCM-sealed into the encrypted body; it never appears on
//! disk in the clear. An explicit binary layout (not CBOR) keeps the bytes byte-for-byte
//! reproducible across languages without depending on a canonical-CBOR implementation (design
//! §13.1 FIX-1). Layout (all lengths are u32 little-endian):
//!
//! ```text
//! title:        len ‖ utf8
//! primary_type: len ‖ utf8
//! source_bundle: present:u8 (0|1) ‖ [ len ‖ utf8 ]
//! is_color_code: u8 (0|1)
//! rep_count:    u32
//! reps×:        uttype(len ‖ utf8) ‖ data(len ‖ bytes)
//! ```

use crate::error::CoreError;

use super::{RecordPlaintext, RecordRepresentation};

/// Upper bound on representations in one record (defense-in-depth; a real clip has a handful).
const MAX_REPRESENTATIONS: u32 = 4096;

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Serialise a plaintext body to its canonical bytes.
pub(super) fn encode_plaintext(p: &RecordPlaintext) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, p.title.as_bytes());
    put_bytes(&mut out, p.primary_type.as_bytes());
    match &p.source_bundle {
        Some(s) => {
            out.push(1);
            put_bytes(&mut out, s.as_bytes());
        }
        None => out.push(0),
    }
    out.push(u8::from(p.is_color_code));
    out.extend_from_slice(&(p.representations.len() as u32).to_le_bytes());
    for rep in &p.representations {
        put_bytes(&mut out, rep.uttype.as_bytes());
        put_bytes(&mut out, &rep.data);
    }
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CoreError> {
        let b = *self.buf.get(self.pos).ok_or(CoreError::UnsupportedFormat)?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> Result<u32, CoreError> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or(CoreError::UnsupportedFormat)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CoreError::UnsupportedFormat)?;
        self.pos = end;
        Ok(u32::from_le_bytes(slice.try_into().expect("4-byte slice")))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, CoreError> {
        let len = self.read_u32()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CoreError::UnsupportedFormat)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CoreError::UnsupportedFormat)?;
        self.pos = end;
        Ok(slice.to_vec())
    }

    fn read_string(&mut self) -> Result<String, CoreError> {
        String::from_utf8(self.read_bytes()?).map_err(|_| CoreError::UnsupportedFormat)
    }
}

/// Parse canonical bytes back into a plaintext body. Rejects trailing garbage and malformed
/// length/flag fields. (Length counts come from already-authenticated ciphertext, but we never
/// pre-allocate from an untrusted count — the loop bails as soon as the buffer is exhausted.)
pub(super) fn decode_plaintext(buf: &[u8]) -> Result<RecordPlaintext, CoreError> {
    let mut r = Reader::new(buf);
    let title = r.read_string()?;
    let primary_type = r.read_string()?;
    let source_bundle = match r.read_u8()? {
        0 => None,
        1 => Some(r.read_string()?),
        _ => return Err(CoreError::UnsupportedFormat),
    };
    let is_color_code = match r.read_u8()? {
        0 => false,
        1 => true,
        _ => return Err(CoreError::UnsupportedFormat),
    };
    let count = r.read_u32()?;
    // Sanity cap. The read loop is already self-limiting (each iteration consumes ≥4 bytes and
    // bails when the buffer is exhausted, and we only decode AES-GCM-authenticated bytes), but a
    // hard ceiling on representations is cheap defense-in-depth against a forged-yet-valid body.
    if count > MAX_REPRESENTATIONS {
        return Err(CoreError::UnsupportedFormat);
    }
    let mut representations = Vec::new();
    for _ in 0..count {
        let uttype = r.read_string()?;
        let data = r.read_bytes()?;
        representations.push(RecordRepresentation { uttype, data });
    }
    if r.pos != buf.len() {
        return Err(CoreError::UnsupportedFormat);
    }
    Ok(RecordPlaintext {
        title,
        primary_type,
        source_bundle,
        is_color_code,
        representations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absurd_rep_count() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // title: len 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // primary_type: len 0
        buf.push(0); // source_bundle: absent
        buf.push(0); // is_color_code: false
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // rep_count: absurd
        assert_eq!(decode_plaintext(&buf), Err(CoreError::UnsupportedFormat));
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut buf = encode_plaintext(&RecordPlaintext {
            title: "x".into(),
            primary_type: "t".into(),
            source_bundle: None,
            is_color_code: false,
            representations: vec![],
        });
        buf.push(0xFF);
        assert_eq!(decode_plaintext(&buf), Err(CoreError::UnsupportedFormat));
    }
}
