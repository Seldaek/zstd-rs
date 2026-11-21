//! This module contains the decompress_literals function, used to take a
//! parsed literals header and a source and decompress it.

use super::super::blocks::literals_section::{LiteralsSection, LiteralsSectionType};
use super::scratch::HuffmanScratch;
use crate::bit_io::{BitReaderReversed, FastBits};
use crate::decoding::errors::DecompressLiteralsError;
use crate::huff0::Entry;
use alloc::vec::Vec;

/// Decode and decompress the provided literals section into `target`, returning the number of bytes read.
pub fn decode_literals(
    section: &LiteralsSection,
    scratch: &mut HuffmanScratch,
    source: &[u8],
    target: &mut Vec<u8>,
) -> Result<u32, DecompressLiteralsError> {
    match section.ls_type {
        LiteralsSectionType::Raw => {
            target.extend(&source[0..section.regenerated_size as usize]);
            Ok(section.regenerated_size)
        }
        LiteralsSectionType::RLE => {
            target.resize(target.len() + section.regenerated_size as usize, source[0]);
            Ok(1)
        }
        LiteralsSectionType::Compressed | LiteralsSectionType::Treeless => {
            let bytes_read = decompress_literals(section, scratch, source, target)?;

            //return sum of used bytes
            Ok(bytes_read)
        }
    }
}

/// Decompress the provided literals section and source into the provided `target`.
/// This function is used when the literals section is `Compressed` or `Treeless`
///
/// Returns the number of bytes read.
fn decompress_literals(
    section: &LiteralsSection,
    scratch: &mut HuffmanScratch,
    source: &[u8],
    target: &mut Vec<u8>,
) -> Result<u32, DecompressLiteralsError> {
    use DecompressLiteralsError as err;

    let compressed_size = section.compressed_size.ok_or(err::MissingCompressedSize)? as usize;
    let num_streams = section.num_streams.ok_or(err::MissingNumStreams)?;

    target.reserve(section.regenerated_size as usize);
    let source = &source[0..compressed_size];
    let mut bytes_read = 0;

    match section.ls_type {
        LiteralsSectionType::Compressed => {
            //read Huffman tree description
            bytes_read += scratch.table.build_decoder(source)?;
            vprintln!("Built huffman table using {} bytes", bytes_read);
        }
        LiteralsSectionType::Treeless if scratch.table.max_num_bits == 0 => {
            return Err(err::UninitializedHuffmanTable);
        }

        _ => { /* nothing to do, huffman tree has been provided by previous block */ }
    }

    let source = &source[bytes_read as usize..];
    let regenerated = section.regenerated_size as usize;
    let table = scratch.table.entries();
    let max_bits = scratch.table.max_num_bits;
    let start = target.len();
    target.resize(start + regenerated, 0);
    let out = &mut target[start..];

    if num_streams == 4 {
        // libzstd's limits for splitting into four streams
        if regenerated < 6 || source.len() < 10 {
            return Err(err::TooSmallForFourStreams {
                literals: regenerated,
                bytes: source.len(),
            });
        }
        let jump1 = source[0] as usize + ((source[1] as usize) << 8);
        let jump2 = jump1 + source[2] as usize + ((source[3] as usize) << 8);
        let jump3 = jump2 + source[4] as usize + ((source[5] as usize) << 8);
        bytes_read += 6;
        let source = &source[6..];

        if source.len() < jump3 {
            return Err(err::MissingBytesForLiterals {
                got: source.len(),
                needed: jump3,
            });
        }

        // each of the first three streams decodes to exactly a quarter (rounded up), the last one to the rest
        let segment = regenerated.div_ceil(4);
        let mut readers = [
            init_reader(&source[..jump1])?,
            init_reader(&source[jump1..jump2])?,
            init_reader(&source[jump2..jump3])?,
            init_reader(&source[jump3..])?,
        ];
        let decoded = decode_four_streams(table, max_bits, &mut readers, out, segment);
        for (k, br) in readers.iter_mut().enumerate() {
            let end = (segment * (k + 1)).min(regenerated);
            decode_stream_rest(br, &mut out[segment * k + decoded..end], table, max_bits)?;
        }

        bytes_read += source.len() as u32;
    } else {
        //just decode the one stream
        assert!(num_streams == 1);
        let mut br = init_reader(source)?;
        decode_stream_rest(&mut br, out, table, max_bits)?;
        bytes_read += source.len() as u32;
    }

    if target.len() != section.regenerated_size as usize {
        return Err(DecompressLiteralsError::DecodedLiteralCountMismatch {
            decoded: target.len(),
            expected: section.regenerated_size as usize,
        });
    }

    Ok(bytes_read)
}

/// A reader for a Huffman stream, positioned after the padding that ends it.
fn init_reader(stream: &[u8]) -> Result<BitReaderReversed<'_>, DecompressLiteralsError> {
    let mut br = BitReaderReversed::new(stream);
    //skip the 0 padding at the end of the last byte of the bit stream and throw away the first 1 found
    let mut skipped_bits = 0;
    loop {
        let val = br.get_bits(1);
        skipped_bits += 1;
        if val == 1 || skipped_bits > 8 {
            break;
        }
    }
    if skipped_bits > 8 {
        //if more than 7 bits are 0, this is not the correct end of the bitstream. Either a bug or corrupted data
        return Err(DecompressLiteralsError::ExtraPadding { skipped_bits });
    }
    Ok(br)
}

/// Decodes the four streams in lockstep for as long as all of them can refill unchecked, each to its
/// `segment` of `out`. Leaves `readers` after the last symbol decoded and returns how many each stream
/// decoded.
fn decode_four_streams<'a>(
    table: &[Entry],
    max_bits: u8,
    readers: &mut [BitReaderReversed<'a>; 4],
    out: &mut [u8],
    segment: usize,
) -> usize {
    /// Five symbols of up to 11 bits fit in the 56 bits a refill provides.
    const SYMBOLS: usize = 5;
    let (Some(a), Some(b), Some(c), Some(d)) = (
        FastBits::new(&readers[0]),
        FastBits::new(&readers[1]),
        FastBits::new(&readers[2]),
        FastBits::new(&readers[3]),
    ) else {
        return 0;
    };
    let mut bits = [a, b, c, d];
    // the table has a power of two entries, masking the index instead of checking it
    let mask = table.len().wrapping_sub(1);
    let shift = 64 - u32::from(max_bits);
    if table.is_empty()
        || shift >= 64
        || u32::from(max_bits) * SYMBOLS as u32 > FastBits::AFTER_REFILL
    {
        return 0;
    }
    // symbols are written 8 bytes at a time, which must stay within the stream's segment
    let last_segment = out.len() - 3 * segment;
    let mut decoded = 0;
    loop {
        let mut rounds = last_segment.saturating_sub(decoded + 8 - SYMBOLS) / SYMBOLS;
        for bits in &bits {
            rounds = rounds.min(bits.refills_left());
        }
        if rounds == 0 {
            break;
        }
        for _ in 0..rounds {
            for (k, bits) in bits.iter_mut().enumerate() {
                bits.refill();
                let mut symbols = 0u64;
                for i in 0..SYMBOLS {
                    let entry = table[bits.peek_top(shift) as usize & mask];
                    bits.consume(u32::from(entry.num_bits));
                    symbols |= u64::from(entry.symbol) << (8 * i);
                }
                let at = segment * k + decoded;
                out[at..at + 8].copy_from_slice(&symbols.to_le_bytes());
            }
            decoded += SYMBOLS;
        }
    }
    let [a, b, c, d] = bits;
    *readers = [
        a.into_reader(),
        b.into_reader(),
        c.into_reader(),
        d.into_reader(),
    ];
    decoded
}

/// Decodes one symbol; the reader must hold at least `max_bits` refilled bits.
#[inline(always)]
fn decode_symbol(br: &mut BitReaderReversed<'_>, table: &[Entry], max_bits: u8) -> u8 {
    let entry = table[br.peek_bits_unchecked(max_bits) as usize];
    br.consume(entry.num_bits);
    entry.symbol
}

/// Fills `out` from the stream, which must then be used up exactly.
fn decode_stream_rest(
    br: &mut BitReaderReversed<'_>,
    out: &mut [u8],
    table: &[Entry],
    max_bits: u8,
) -> Result<(), DecompressLiteralsError> {
    for chunk in out.chunks_mut(5) {
        br.refill();
        for byte in chunk {
            *byte = decode_symbol(br, table, max_bits);
        }
    }
    if br.bits_remaining() != 0 {
        return Err(DecompressLiteralsError::BitstreamReadMismatch {
            read_til: br.bits_remaining(),
            expected: 0,
        });
    }
    Ok(())
}
