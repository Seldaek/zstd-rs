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
        };
        let result = reader.for_each_fast(|seq| exec.execute(seq));
        let result = result.and_then(|()| {
            while let Some(seq) = reader.next() {
                exec.execute(seq)?;
            }
            Ok(())
        });
        hist = exec.hist;
        result?;
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
}

impl Executor<'_> {
    #[inline(always)]
    fn execute(&mut self, seq: Sequence) -> Result<(), ExecuteSequencesError> {
        let (ll, ml) = (seq.ll as usize, seq.ml as usize);
        let (pos, lit) = (self.pos, self.lit);
        if lit + ll > self.literals_len {
            return Err(ExecuteSequencesError::NotEnoughBytesForSequence {
                wanted: lit + ll,
                have: self.literals_len,
            });
        }
        // checked before writing
        if pos + ll + ml > self.limit {
            return Err(ExecuteSequencesError::TooManyBytesGenerated {
                max: self.limit - self.start,
                decoded: pos + ll + ml - self.start,
            });
        }
        self.buf[pos..pos + 16].copy_from_slice(&self.literals[lit..lit + 16]);
        if ll > 16 {
            self.buf[pos + 16..pos + ll].copy_from_slice(&self.literals[lit + 16..lit + ll]);
        }
        let pos = pos + ll;
        self.lit = lit + ll;
        self.pos = pos;

        let offset = do_offset_history(seq.of, seq.ll, &mut self.hist) as usize;
        if offset == 0 {
            return Err(ExecuteSequencesError::ZeroOffset);
        }
        if offset > pos {
            return Err(ExecuteSequencesError::DecodebufferError(
                DecodeBufferError::OffsetTooBig {
                    offset,
                    buf_len: pos,
                },
            ));
        }
        copy_match(self.buf, pos, offset, ml);
        self.pos = pos + ml;
        Ok(())
    }
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
    let [h0, h1, h2] = *scratch;
    if offset_value > 3 {
        let actual_offset = offset_value - 3;
        *scratch = [actual_offset, h0, h1];
        return actual_offset;
    }
    // Repeat offsets, shifted by one when there are no literals: the last one is then the most recent
    // offset minus one. A malformed dictionary can seed it with 0; saturate so this resolves to 0
    // (rejected as ZeroOffset) instead of underflowing. See #115.
    let idx = offset_value.wrapping_sub(1) + u32::from(lit_len == 0);
    let actual_offset = match idx {
        0 => h0,
        1 => h1,
        2 => h2,
        _ => h0.saturating_sub(1),
    };
    *scratch = [
        actual_offset,
        if idx >= 1 { h0 } else { h1 },
        if idx >= 2 { h1 } else { h2 },
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
