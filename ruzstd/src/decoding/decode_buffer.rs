use crate::io::{Error, Read, Write};
use alloc::vec::Vec;
#[cfg(feature = "hash")]
use core::hash::Hasher;

use crate::common::MAX_BLOCK_SIZE;
use crate::decoding::errors::DecodeBufferError;

/// Bytes past `end` that wild copies may overwrite.
pub(crate) const SLACK: usize = 32;

/// Decoded output of the current frame.
///
/// A flat, fully initialized buffer: `buf[..end]` is the history matches can refer to, `buf[drained..end]` is
/// output not handed out yet. When it runs out of space, the part still needed (the last `window_size` bytes
/// and anything not drained) moves to the front, so there are no wrap-arounds to handle while decoding.
pub struct DecodeBuffer {
    buf: Vec<u8>,
    end: usize,
    drained: usize,
    pub dict_content: Vec<u8>,

    pub window_size: usize,
    /// How much the current frame is expected to need, to size the buffer once.
    expected_size: usize,
    total_output_counter: u64,
    #[cfg(feature = "hash")]
    pub hash: twox_hash::XxHash64,
}

impl Read for DecodeBuffer {
    fn read(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        self.read_all(target)
    }
}

impl DecodeBuffer {
    pub fn new(window_size: usize) -> DecodeBuffer {
        DecodeBuffer {
            buf: Vec::new(),
            end: 0,
            drained: 0,
            dict_content: Vec::new(),
            window_size,
            expected_size: window_size,
            total_output_counter: 0,
            #[cfg(feature = "hash")]
            hash: twox_hash::XxHash64::with_seed(0),
        }
    }

    pub fn reset(&mut self, window_size: usize) {
        self.window_size = window_size;
        self.expected_size = window_size;
        self.end = 0;
        self.drained = 0;
        self.dict_content.clear();
        self.total_output_counter = 0;
        #[cfg(feature = "hash")]
        {
            self.hash = twox_hash::XxHash64::with_seed(0);
        }
    }

    /// Sizes the next allocation for a frame expected to keep this many bytes of history.
    pub fn set_expected_size(&mut self, size: usize) {
        self.expected_size = size;
    }

    /// Bytes decoded but not drained yet.
    pub fn len(&self) -> usize {
        self.end - self.drained
    }

    /// Makes room for writing `amount` bytes (plus `SLACK`) at `end`.
    #[inline(always)]
    fn ensure(&mut self, amount: usize) {
        if self.buf.len() - self.end < amount + SLACK {
            self.make_room(amount);
        }
    }

    #[cold]
    fn make_room(&mut self, amount: usize) {
        let keep_from = self.drained.min(self.end.saturating_sub(self.window_size));
        let kept = self.end - keep_from;
        let needed = kept + amount + SLACK;
        // only move what frees at least half as much space, amortized to two extra copies per byte
        if keep_from >= kept / 2 && self.buf.len() >= needed {
            self.buf.copy_within(keep_from..self.end, 0);
        } else {
            // a fresh zeroed allocation is provided lazily by the OS, unlike zeroing the grown part in place;
            // sized for the whole frame first, so most frames allocate once
            let first = self.expected_size + 2 * MAX_BLOCK_SIZE as usize + SLACK;
            let grown = if self.buf.len() < first {
                first
            } else {
                2 * needed
            };
            let mut buf = alloc::vec![0u8; grown.max(needed)];
            buf[..kept].copy_from_slice(&self.buf[keep_from..self.end]);
            self.buf = buf;
        }
        self.end -= keep_from;
        self.drained -= keep_from;
    }

    /// Writes `amount` bytes at `end` with `write`, which may write up to `SLACK` bytes more.
    #[inline(always)]
    pub(crate) fn write_with(&mut self, amount: usize, write: impl FnOnce(&mut [u8], usize)) {
        self.ensure(amount);
        write(&mut self.buf, self.end);
        self.end += amount;
        self.total_output_counter += amount as u64;
    }

    /// Runs `write` on the buffer and the current end, with room for `max` bytes plus `SLACK` past it.
    /// `write` returns the new end, at most `max` bytes further.
    #[inline(always)]
    pub(crate) fn write_block<E>(
        &mut self,
        max: usize,
        write: impl FnOnce(&mut [u8], usize) -> Result<usize, E>,
    ) -> Result<(), E> {
        self.ensure(max);
        let end = self.end;
        let new_end = write(&mut self.buf, end)?;
        debug_assert!(new_end >= end && new_end - end <= max);
        self.total_output_counter += (new_end - end) as u64;
        self.end = new_end;
        Ok(())
    }

    pub fn extend_and_fill(&mut self, fill_with: u8, fill_length: usize) {
        self.write_with(fill_length, |buf, end| {
            buf[end..end + fill_length].fill(fill_with)
        });
    }

    pub fn extend_from_reader<R: Read>(
        &mut self,
        mut read: R,
        fill_length: usize,
    ) -> Result<(), crate::io::Error> {
        self.ensure(fill_length);
        read.read_exact(&mut self.buf[self.end..self.end + fill_length])?;
        self.end += fill_length;
        self.total_output_counter += fill_length as u64;
        Ok(())
    }

    #[inline(always)]
    pub fn push(&mut self, data: &[u8]) {
        let len = data.len();
        self.write_with(len, |buf, end| buf[end..end + len].copy_from_slice(data));
    }

    #[inline(always)]
    pub fn repeat(&mut self, offset: usize, match_length: usize) -> Result<(), DecodeBufferError> {
        if offset > self.end {
            return self.repeat_from_dict(offset, match_length);
        }
        self.write_with(match_length, |buf, end| {
            copy_match(buf, end, offset, match_length)
        });
        Ok(())
    }

    #[cold]
    fn repeat_from_dict(
        &mut self,
        offset: usize,
        match_length: usize,
    ) -> Result<(), DecodeBufferError> {
        if self.total_output_counter <= self.window_size as u64 {
            // at least part of that repeat is from the dictionary content
            let bytes_from_dict = offset - self.end;

            if bytes_from_dict > self.dict_content.len() {
                return Err(DecodeBufferError::NotEnoughBytesInDictionary {
                    got: self.dict_content.len(),
                    need: bytes_from_dict,
                });
            }

            let low = self.dict_content.len() - bytes_from_dict;
            let from_dict = bytes_from_dict.min(match_length);
            let dict = core::mem::take(&mut self.dict_content);
            self.push(&dict[low..low + from_dict]);
            self.dict_content = dict;
            if from_dict < match_length {
                return self.repeat(self.end, match_length - from_dict);
            }
            Ok(())
        } else {
            Err(DecodeBufferError::OffsetTooBig {
                offset,
                buf_len: self.end,
            })
        }
    }

    /// Check if and how many bytes can currently be drawn from the buffer
    pub fn can_drain_to_window_size(&self) -> Option<usize> {
        if self.len() > 0 {
            Some(self.len())
        } else {
            None
        }
    }

    //How many bytes can be drained if the window_size does not have to be maintained
    pub fn can_drain(&self) -> usize {
        self.len()
    }

    /// Drain everything not drained yet; the history needed for decoding is kept separately.
    pub fn drain_to_window_size(&mut self) -> Option<Vec<u8>> {
        self.can_drain_to_window_size()?;
        Some(self.drain())
    }

    pub fn drain_to_window_size_writer(&mut self, sink: impl Write) -> Result<usize, Error> {
        self.drain_to_writer(sink)
    }

    /// drain the buffer completely
    pub fn drain(&mut self) -> Vec<u8> {
        let out = self.buf[self.drained..self.end].to_vec();
        #[cfg(feature = "hash")]
        self.hash.write(&out);
        self.drained = self.end;
        out
    }

    pub fn drain_to_writer(&mut self, mut sink: impl Write) -> Result<usize, Error> {
        let amount = self.len();
        self.drain_to(amount, |buf| write_all_bytes(&mut sink, buf))
    }

    pub fn read_all(&mut self, target: &mut [u8]) -> Result<usize, Error> {
        let amount = self.len().min(target.len());
        self.drain_to(amount, |buf| {
            target[..buf.len()].copy_from_slice(buf);
            (buf.len(), Ok(()))
        })
    }

    /// Semantics of write_bytes:
    /// Should dump as many of the provided bytes as possible to whatever sink until no bytes are left or an error is encountered
    /// Return how many bytes have actually been dumped to the sink.
    fn drain_to(
        &mut self,
        amount: usize,
        mut write_bytes: impl FnMut(&[u8]) -> (usize, Result<(), Error>),
    ) -> Result<usize, Error> {
        if amount == 0 {
            return Ok(0);
        }
        let slice = &self.buf[self.drained..self.drained + amount];
        let (written, res) = write_bytes(slice);
        #[cfg(feature = "hash")]
        self.hash.write(&slice[..written]);
        self.drained += written;
        res?;
        Ok(written)
    }
}

/// Appends `len` bytes at `end`, copied from `offset` bytes back, with LZ77 semantics: when `offset < len`,
/// the copy repeats the bytes it is writing. May write up to `SLACK` bytes past `end + len`.
#[inline(always)]
pub(crate) fn copy_match(buf: &mut [u8], end: usize, offset: usize, len: usize) {
    if offset >= 16 {
        // 16 byte chunks only read bytes that are final already
        let src = end - offset;
        let mut i = 0;
        while i < len {
            buf.copy_within(src + i..src + i + 16, end + i);
            i += 16;
        }
    } else {
        copy_match_short_offset(buf, end, offset, len);
    }
}

/// The pattern repeats every `offset` bytes. Copying 16 bytes onto the end of what is valid so far doubles it,
/// the bytes copied beyond that are overwritten by the next copy. Once at least 16 bytes are valid, the rest
/// copies in 16 byte chunks from that distance, a multiple of `offset`.
#[inline(never)]
fn copy_match_short_offset(buf: &mut [u8], end: usize, offset: usize, len: usize) {
    let start = end - offset;
    let mut distance = offset;
    while distance < 16 {
        buf.copy_within(start..start + 16, start + distance);
        distance *= 2;
    }
    let mut i = start + distance;
    while i < end + len {
        buf.copy_within(i - distance..i - distance + 16, i);
        i += 16;
    }
}

/// Like Write::write_all but returns partial write length even on error
fn write_all_bytes(mut sink: impl Write, buf: &[u8]) -> (usize, Result<(), Error>) {
    let mut written = 0;
    while written < buf.len() {
        match sink.write(&buf[written..]) {
            Ok(0) => return (written, Ok(())),
            Ok(w) => written += w,
            Err(e) => return (written, Err(e)),
        }
    }
    (written, Ok(()))
}

#[cfg(test)]
mod tests {
    use super::DecodeBuffer;
    use crate::io::{Error, ErrorKind, Write};

    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn short_writer() {
        struct ShortWriter {
            buf: Vec<u8>,
            write_len: usize,
        }

        impl Write for ShortWriter {
            fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Error> {
                if buf.len() > self.write_len {
                    self.buf.extend_from_slice(&buf[..self.write_len]);
                    Ok(self.write_len)
                } else {
                    self.buf.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }

            fn flush(&mut self) -> std::result::Result<(), Error> {
                Ok(())
            }
        }

        let mut short_writer = ShortWriter {
            buf: vec![],
            write_len: 10,
        };

        let mut decode_buf = DecodeBuffer::new(100);
        decode_buf.push(b"0123456789");
        decode_buf.repeat(10, 90).unwrap();
        let repeats = 1000;
        decode_buf
            .drain_to_window_size_writer(&mut short_writer)
            .unwrap();
        for _ in 0..repeats {
            assert_eq!(decode_buf.len(), 0);
            decode_buf.repeat(10, 50).unwrap();
            assert_eq!(decode_buf.len(), 50);
            decode_buf
                .drain_to_window_size_writer(&mut short_writer)
                .unwrap();
        }

        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
        decode_buf.drain_to_writer(&mut short_writer).unwrap();
        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
        let expected: Vec<u8> = b"0123456789"
            .iter()
            .copied()
            .cycle()
            .take(repeats * 50 + 100)
            .collect();
        assert_eq!(short_writer.buf, expected);
    }

    #[test]
    fn wouldblock_writer() {
        struct WouldblockWriter {
            buf: Vec<u8>,
            last_blocked: usize,
            block_every: usize,
        }

        impl Write for WouldblockWriter {
            fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, Error> {
                if self.last_blocked < self.block_every {
                    self.buf.extend_from_slice(buf);
                    self.last_blocked += 1;
                    Ok(buf.len())
                } else {
                    self.last_blocked = 0;
                    Err(Error::from(ErrorKind::WouldBlock))
                }
            }

            fn flush(&mut self) -> std::result::Result<(), Error> {
                Ok(())
            }
        }

        let mut short_writer = WouldblockWriter {
            buf: vec![],
            last_blocked: 0,
            block_every: 5,
        };

        let mut decode_buf = DecodeBuffer::new(100);
        decode_buf.push(b"0123456789");
        decode_buf.repeat(10, 90).unwrap();
        let repeats = 1000;
        for _ in 0..repeats {
            decode_buf.repeat(10, 50).unwrap();
            loop {
                match decode_buf.drain_to_window_size_writer(&mut short_writer) {
                    Ok(written) => {
                        if written == 0 {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            continue;
                        } else {
                            panic!("Unexpected error {:?}", e);
                        }
                    }
                }
            }
            assert_eq!(decode_buf.len(), 0);
        }

        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
        loop {
            match decode_buf.drain_to_writer(&mut short_writer) {
                Ok(written) => {
                    if written == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        continue;
                    } else {
                        panic!("Unexpected error {:?}", e);
                    }
                }
            }
        }
        assert_eq!(short_writer.buf.len(), repeats * 50 + 100);
    }
}
