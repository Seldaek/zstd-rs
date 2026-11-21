use super::decode_buffer::DecodeBuffer;
use super::decode_buffer::{copy_match, SLACK};
use super::scratch::{DecoderScratch, FSEScratch};
use super::sequence_section_decoder::read_sequences;
use crate::blocks::sequence_section::{Sequence, SequencesHeader};
use crate::decoding::errors::{DecodeBufferError, DecompressBlockError, ExecuteSequencesError};
use alloc::vec::Vec;

/// Take the provided decoder and execute the sequences stored within
/// Decodes and executes a block's sequences in one pass, for frames without a dictionary.
pub(crate) fn decode_and_execute_sequences(
    section: &SequencesHeader,
    source: &[u8],
    fse: &mut FSEScratch,
    buffer: &mut DecodeBuffer,
    literals_buffer: &mut Vec<u8>,
    offset_hist: &mut [u32; 3],
    max_block_decoded_len: usize,
) -> Result<(), DecompressBlockError> {
    debug_assert!(buffer.dict_content.is_empty());
    let mut reader = read_sequences(section, source, fse)?;
    // wild copies of short literals read up to SLACK bytes past them
    let literals_len = literals_buffer.len();
    literals_buffer.resize(literals_len + SLACK, 0);
    let literals: &[u8] = literals_buffer;
    let mut hist = *offset_hist;
    let result = buffer.write_block(max_block_decoded_len, |buf, start| {
        let mut exec = Executor {
            buf,
            literals,
            literals_len,
            start,
            pos: start,
            lit: 0,
            hist,
            limit: start + max_block_decoded_len,
            error: None,
        };
        reader.for_each_fast(|seq| exec.execute(seq));
        if exec.error.is_none() {
            while let Some(seq) = reader.next() {
                if !exec.execute(seq) {
                    break;
                }
            }
        }
        hist = exec.hist;
        if let Some(error) = exec.error {
            return Err(error);
        }
        let (pos, lit) = (exec.pos, exec.lit);
        let rest = literals_len - lit;
        if pos + rest > exec.limit {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: max_block_decoded_len,
                decoded: pos - start + rest,
            });
        }
        exec.buf[pos..pos + rest].copy_from_slice(&literals[lit..literals_len]);
        Ok(pos + rest)
    });
    *offset_hist = hist;
    literals_buffer.truncate(literals_len);
    result?;
    reader.finish()?;
    Ok(())
}

/// Where a block's sequences are executed: output and literals with the positions reached in them.
struct Executor<'a> {
    buf: &'a mut [u8],
    /// Padded with `SLACK` bytes after `literals_len`.
    literals: &'a [u8],
    literals_len: usize,
    /// Where the block starts in `buf`.
    start: usize,
    pos: usize,
    lit: usize,
    hist: [u32; 3],
    /// The block's output may not go past this, the buffer only has `SLACK` bytes of room after it.
    limit: usize,
    /// Why `execute` returned false.
    error: Option<ExecuteSequencesError>,
}

impl Executor<'_> {
    /// Returns false and sets `error` when the sequence is invalid.
    #[inline(always)]
    fn execute(&mut self, seq: Sequence) -> bool {
        let (ll, ml) = (seq.ll as usize, seq.ml as usize);
        let (pos, lit) = (self.pos, self.lit);
        let literals_end = pos + ll;
        let end = literals_end + ml;
        // checked before writing
        if lit + ll > self.literals_len || end > self.limit {
            self.error = Some(length_error(
                lit + ll,
                self.literals_len,
                end - self.start,
                self.limit - self.start,
            ));
            return false;
        }
        self.buf[pos..pos + 16].copy_from_slice(&self.literals[lit..lit + 16]);

        let offset = do_offset_history(seq.of, seq.ll, &mut self.hist) as usize;
        // also true for 0, which wraps
        if offset.wrapping_sub(1) >= literals_end {
            self.error = Some(offset_error(offset, literals_end));
            return false;
        }
        if ll > 16 || offset < 32 {
            copy_uncommon(self.buf, pos, &self.literals[lit..lit + ll], offset, ml);
        } else {
            // 32 byte chunks only read bytes that are final already; most matches fit in one, and going on
            // per 32 bytes keeps the exit of this loop predictable
            let src = literals_end - offset;
            let mut i = 0;
            loop {
                self.buf
                    .copy_within(src + i..src + i + 32, literals_end + i);
                i += 32;
                if i >= ml {
                    break;
                }
            }
        }
        self.lit = lit + ll;
        self.pos = end;
        true
    }
}

#[cold]
#[inline(never)]
fn length_error(
    literals_wanted: usize,
    literals_len: usize,
    decoded: usize,
    max: usize,
) -> ExecuteSequencesError {
    if literals_wanted > literals_len {
        ExecuteSequencesError::NotEnoughBytesForSequence {
            wanted: literals_wanted,
            have: literals_len,
        }
    } else {
        ExecuteSequencesError::TooManyBytesGenerated { max, decoded }
    }
}

#[cold]
#[inline(never)]
fn offset_error(offset: usize, buf_len: usize) -> ExecuteSequencesError {
    if offset == 0 {
        ExecuteSequencesError::ZeroOffset
    } else {
        ExecuteSequencesError::DecodebufferError(DecodeBufferError::OffsetTooBig {
            offset,
            buf_len,
        })
    }
}

/// Long literals and short offsets are rare. Keeping their calls out of the loop executing sequences, and
/// cold, lets it keep its state in registers.
#[cold]
#[inline(never)]
fn copy_uncommon(buf: &mut [u8], pos: usize, literals: &[u8], offset: usize, ml: usize) {
    let literals_end = pos + literals.len();
    buf[pos..literals_end].copy_from_slice(literals);
    copy_match(buf, literals_end, offset, ml);
}

/// Executes the sequences decoded into the scratch, where matches may also reach into the dictionary.
pub fn execute_sequences(
    scratch: &mut DecoderScratch,
    max_block_decoded_len: usize,
) -> Result<(), ExecuteSequencesError> {
    let mut literals_copy_counter = 0;
    let old_buffer_size = scratch.buffer.len();
    let mut seq_sum = 0;

    for idx in 0..scratch.sequences.len() {
        let seq = scratch.sequences[idx];

        if seq.ll > 0 {
            let high = literals_copy_counter + seq.ll as usize;
            if high > scratch.literals_buffer.len() {
                return Err(ExecuteSequencesError::NotEnoughBytesForSequence {
                    wanted: high,
                    have: scratch.literals_buffer.len(),
                });
            }
            let literals = &scratch.literals_buffer[literals_copy_counter..high];
            literals_copy_counter += seq.ll as usize;

            scratch.buffer.push(literals);
        }

        let actual_offset = do_offset_history(seq.of, seq.ll, &mut scratch.offset_hist);
        if actual_offset == 0 {
            return Err(ExecuteSequencesError::ZeroOffset);
        }
        if seq.ml > 0 {
            scratch
                .buffer
                .repeat(actual_offset as usize, seq.ml as usize)?;
        }

        seq_sum += seq.ml;
        seq_sum += seq.ll;

        if seq_sum as usize > max_block_decoded_len {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: max_block_decoded_len,
                decoded: seq_sum as usize,
            });
        }
    }
    if literals_copy_counter < scratch.literals_buffer.len() {
        let rest_literals = &scratch.literals_buffer[literals_copy_counter..];
        scratch.buffer.push(rest_literals);
        seq_sum += rest_literals.len() as u32;
        if seq_sum as usize > max_block_decoded_len {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: max_block_decoded_len,
                decoded: seq_sum as usize,
            });
        }
    }

    let diff = scratch.buffer.len() - old_buffer_size;
    assert!(
        seq_sum as usize == diff,
        "Seq_sum: {} is different from the difference in buffersize: {}",
        seq_sum,
        diff
    );
    Ok(())
}

/// Update the most recently used offsets to reflect the provided offset value, and return the
/// "actual" offset needed because offsets are not stored in a raw way, some transformations are needed
/// before you get a functional number.
#[inline(always)]
fn do_offset_history(offset_value: u32, lit_len: u32, scratch: &mut [u32; 3]) -> u32 {
    /// `a` if `cond`, else `b`. Whether an offset repeats is close to random, so this is spelled out
    /// with masks to compile to conditional moves instead of branches.
    #[inline(always)]
    fn select(cond: bool, a: u32, b: u32) -> u32 {
        let mask = u32::from(cond).wrapping_neg();
        (a & mask) | (b & !mask)
    }

    let [h0, h1, h2] = *scratch;
    let repeat = offset_value <= 3;
    // Which repeat offset: shifted by one when there are no literals, the last one is then the most recent
    // offset minus one. A malformed dictionary can seed it with 0; saturate so this resolves to 0
    // (rejected as ZeroOffset) instead of underflowing. See #115.
    let idx = offset_value.wrapping_sub(1) + u32::from(lit_len == 0);
    let repeated = select(
        idx < 2,
        select(idx == 0, h0, h1),
        select(idx == 2, h2, h0.saturating_sub(1)),
    );
    let actual_offset = select(repeat, repeated, offset_value.wrapping_sub(3));
    *scratch = [
        actual_offset,
        select(repeat && idx == 0, h1, h0),
        select(repeat && idx < 2, h2, h1),
    ];
    actual_offset
}

#[cfg(test)]
mod tests {
    use super::do_offset_history;

    #[test]
    fn repeat_offset_minus_one_with_zero_history_does_not_underflow() {
        // A malformed dictionary can seed offset history slot 0 with 0. With
        // literal length 0 and offset code 3 ("repeat the most recent offset,
        // minus one"), `scratch[0] - 1` must not underflow; it should resolve to
        // 0, which the caller rejects as ExecuteSequencesError::ZeroOffset rather
        // than panicking (debug) or wrapping to u32::MAX (release). See #115.
        let mut scratch = [0u32, 4, 8];
        assert_eq!(do_offset_history(3, 0, &mut scratch), 0);
    }
}
