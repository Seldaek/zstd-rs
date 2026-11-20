//! This module contains the decompress_literals function, used to take a
//! parsed literals header and a source and decompress it.

use super::super::blocks::literals_section::{LiteralsSection, LiteralsSectionType};
use super::scratch::HuffmanScratch;
use crate::bit_io::BitReaderReversed;
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
        let (out1, rest) = out.split_at_mut(segment);
        let (out2, rest) = rest.split_at_mut(segment);
        let (out3, out4) = rest.split_at_mut(segment);
        let mut readers = [
            init_reader(&source[..jump1])?,
            init_reader(&source[jump1..jump2])?,
            init_reader(&source[jump2..jump3])?,
            init_reader(&source[jump3..])?,
        ];
        let mut outs = [out1, out2, out3, out4];

        // all four in lockstep while every reader can refill unchecked: five symbols fit in the 57 bits after a refill
        let mut pos = 0;
        while pos + 5 <= outs[3].len() && readers.iter().all(|br| br.byte_idx() >= 8) {
            for br in &mut readers {
                br.refill_unchecked();
            }
            for k in 0..5 {
                for (br, out) in readers.iter_mut().zip(outs.iter_mut()) {
                    out[pos + k] = decode_symbol(br, table, max_bits);
                }
            }
            pos += 5;
        }
        for (br, out) in readers.iter_mut().zip(outs.iter_mut()) {
            decode_stream_rest(br, &mut out[pos..], table, max_bits)?;
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
