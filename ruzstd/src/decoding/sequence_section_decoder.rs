use super::super::blocks::sequence_section::ModeType;
use super::super::blocks::sequence_section::Sequence;
use super::super::blocks::sequence_section::SequencesHeader;
use super::scratch::{FSEScratch, SeqEntry, SeqTable};
use crate::bit_io::BitReaderReversed;
use crate::blocks::sequence_section::{
    MAX_LITERAL_LENGTH_CODE, MAX_MATCH_LENGTH_CODE, MAX_OFFSET_CODE,
};
use crate::decoding::errors::DecodeSequenceError;
use crate::decoding::errors::FSEDecoderError;
use crate::fse::FSETable;
use alloc::vec::Vec;

/// Decode the provided source as a series of sequences into the supplied `target`.
/// Reads the table descriptions and positions a reader on the sequences of `source`.
pub(crate) fn read_sequences<'a>(
    section: &SequencesHeader,
    source: &'a [u8],
    scratch: &'a mut FSEScratch,
) -> Result<SequenceReader<'a>, DecodeSequenceError> {
    let bytes_read = maybe_update_fse_tables(section, source, scratch)?;

    vprintln!("Updating tables used {} bytes", bytes_read);

    let bit_stream = &source[bytes_read..];

    let mut br = BitReaderReversed::new(bit_stream);

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
        return Err(DecodeSequenceError::ExtraPadding { skipped_bits });
    }

    for (i, table) in scratch.seq_tables.iter_mut().enumerate() {
        if table.stale {
            match i {
                0 => build_seq_table(
                    table,
                    &scratch.literal_lengths,
                    scratch.ll_rle,
                    lookup_ll_code,
                    MAX_LITERAL_LENGTH_CODE,
                )?,
                1 => build_seq_table(
                    table,
                    &scratch.match_lengths,
                    scratch.ml_rle,
                    lookup_ml_code,
                    MAX_MATCH_LENGTH_CODE,
                )?,
                _ => build_seq_table(
                    table,
                    &scratch.offsets,
                    scratch.of_rle,
                    |code| (1u32 << code, code),
                    MAX_OFFSET_CODE,
                )?,
            }
            table.stale = false;
        }
    }
    let [ll, ml, of] = &scratch.seq_tables;
    Ok(SequenceReader::new(
        br,
        [ll, ml, of],
        section.num_sequences as usize,
    ))
}

/// Decode the provided source as a series of sequences into the supplied `target`.
pub fn decode_sequences(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
    target: &mut Vec<Sequence>,
) -> Result<(), DecodeSequenceError> {
    let mut reader = read_sequences(section, source, scratch)?;
    target.clear();
    target.reserve(section.num_sequences as usize);
    while let Some(seq) = reader.next() {
        target.push(seq);
    }
    reader.finish()
}

/// Look up the provided state value from a literal length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ll_code(code: u8) -> (u32, u8) {
    match code {
        0..=15 => (u32::from(code), 0),
        16 => (16, 1),
        17 => (18, 1),
        18 => (20, 1),
        19 => (22, 1),
        20 => (24, 2),
        21 => (28, 2),
        22 => (32, 3),
        23 => (40, 3),
        24 => (48, 4),
        25 => (64, 6),
        26 => (128, 7),
        27 => (256, 8),
        28 => (512, 9),
        29 => (1024, 10),
        30 => (2048, 11),
        31 => (4096, 12),
        32 => (8192, 13),
        33 => (16384, 14),
        34 => (32768, 15),
        35 => (65536, 16),
        _ => unreachable!("Illegal literal length code was: {}", code),
    }
}

/// Look up the provided state value from a match length table predefined
/// by the Zstandard reference document. Returns a tuple of (value, number of bits).
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ml_code(code: u8) -> (u32, u8) {
    match code {
        0..=31 => (u32::from(code) + 3, 0),
        32 => (35, 1),
        33 => (37, 1),
        34 => (39, 1),
        35 => (41, 1),
        36 => (43, 2),
        37 => (47, 2),
        38 => (51, 3),
        39 => (59, 3),
        40 => (67, 4),
        41 => (83, 4),
        42 => (99, 5),
        43 => (131, 7),
        44 => (259, 8),
        45 => (515, 9),
        46 => (1027, 10),
        47 => (2051, 11),
        48 => (4099, 12),
        49 => (8195, 13),
        50 => (16387, 14),
        51 => (32771, 15),
        52 => (65539, 16),
        _ => unreachable!("Illegal match length code was: {}", code),
    }
}

// This info is buried in the symbol compression mode table
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const LL_MAX_LOG: u8 = 9;
/// "The maximum allowed accuracy log for literals length and match length tables is 9"
pub const ML_MAX_LOG: u8 = 9;
/// "The maximum accuracy log for the offset table is 8."
pub const OF_MAX_LOG: u8 = 8;

/// Resolves an FSE table (or RLE symbol) into a sequence table.
fn build_seq_table(
    out: &mut SeqTable,
    fse: &FSETable,
    rle: Option<u8>,
    lookup: impl Fn(u8) -> (u32, u8),
    max_code: u8,
) -> Result<(), DecodeSequenceError> {
    out.entries.clear();
    if let Some(code) = rle {
        // a single state that reads no bits
        let (value, extra_bits) = lookup(code);
        out.entries.push(SeqEntry {
            base_line: 0,
            value,
            num_bits: 0,
            extra_bits,
        });
        out.accuracy_log = 0;
        return Ok(());
    }
    if fse.accuracy_log == 0 {
        return Err(FSEDecoderError::TableIsUninitialized.into());
    }
    for e in &fse.decode {
        if e.symbol > max_code {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: e.symbol,
            });
        }
        let (value, extra_bits) = lookup(e.symbol);
        out.entries.push(SeqEntry {
            base_line: e.base_line,
            value,
            num_bits: e.num_bits,
            extra_bits,
        });
    }
    out.accuracy_log = fse.accuracy_log;
    Ok(())
}

/// libzstd's limits: at least 57 bits are readable after a refill, and the three state updates read at most
/// 9 + 9 + 8 bits.
const BITS_AFTER_REFILL: u8 = 57;
const MAX_STATE_BITS: u8 = 26;

#[inline(always)]
fn refill<const UNCHECKED: bool>(br: &mut BitReaderReversed<'_>) {
    if UNCHECKED {
        br.refill_unchecked();
    } else {
        br.refill();
    }
}

/// Decodes one sequence and, unless it is the last one, advances the states. The reader must be refilled.
#[inline(always)]
fn decode_one<const UNCHECKED: bool>(
    br: &mut BitReaderReversed<'_>,
    states: &mut [u32; 3],
    tables: [&[SeqEntry]; 3],
    last: bool,
) -> Sequence {
    let ll = tables[0][states[0] as usize];
    let ml = tables[1][states[1] as usize];
    let of = tables[2][states[2] as usize];
    let extra = of.extra_bits + ml.extra_bits + ll.extra_bits;
    let of_add = br.get_bits_unchecked(of.extra_bits);
    let ml_add = br.get_bits_unchecked(ml.extra_bits);
    if extra > BITS_AFTER_REFILL {
        refill::<UNCHECKED>(br);
    }
    let ll_add = br.get_bits_unchecked(ll.extra_bits);
    if !last {
        if extra > BITS_AFTER_REFILL - MAX_STATE_BITS {
            refill::<UNCHECKED>(br);
        }
        states[0] = ll.base_line + br.get_bits_unchecked(ll.num_bits) as u32;
        states[1] = ml.base_line + br.get_bits_unchecked(ml.num_bits) as u32;
        states[2] = of.base_line + br.get_bits_unchecked(of.num_bits) as u32;
    }
    Sequence {
        ll: ll.value + ll_add as u32,
        ml: ml.value + ml_add as u32,
        of: of.value + of_add as u32,
    }
}

/// Decodes the sequences of a block one by one.
pub(crate) struct SequenceReader<'a> {
    br: BitReaderReversed<'a>,
    states: [u32; 3],
    tables: [&'a [SeqEntry]; 3],
    remaining: usize,
}

impl<'a> SequenceReader<'a> {
    fn new(mut br: BitReaderReversed<'a>, tables: [&'a SeqTable; 3], num_sequences: usize) -> Self {
        let mut states = [0u32; 3];
        states[0] = br.get_bits(tables[0].accuracy_log) as u32;
        states[2] = br.get_bits(tables[2].accuracy_log) as u32;
        states[1] = br.get_bits(tables[1].accuracy_log) as u32;
        SequenceReader {
            br,
            states,
            tables: [&tables[0].entries, &tables[1].entries, &tables[2].entries],
            remaining: num_sequences,
        }
    }

    #[inline(always)]
    pub(crate) fn next(&mut self) -> Option<Sequence> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        // a sequence reads at most 63 + 26 bits, so 16 bytes left in the stream make the unchecked refills safe
        Some(if self.br.byte_idx() > 16 {
            self.br.refill_unchecked();
            decode_one::<true>(
                &mut self.br,
                &mut self.states,
                self.tables,
                self.remaining == 0,
            )
        } else {
            self.br.refill();
            decode_one::<false>(
                &mut self.br,
                &mut self.states,
                self.tables,
                self.remaining == 0,
            )
        })
    }

    /// Runs `f` on sequences for as long as they can be decoded without checked refills, leaving at least the
    /// last one to `next`. Works on copies of the state so it stays in registers.
    #[inline(always)]
    pub(crate) fn for_each_fast<E>(
        &mut self,
        mut f: impl FnMut(Sequence) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut br = self.br.clone();
        let mut states = self.states;
        let mut remaining = self.remaining;
        let mut result = Ok(());
        while remaining > 1 && br.byte_idx() > 16 {
            remaining -= 1;
            br.refill_unchecked();
            let seq = decode_one::<true>(&mut br, &mut states, self.tables, false);
            if let Err(e) = f(seq) {
                result = Err(e);
                break;
            }
        }
        self.br = br;
        self.states = states;
        self.remaining = remaining;
        result
    }

    /// Checks that the bitstream ended exactly with the last sequence.
    pub(crate) fn finish(self) -> Result<(), DecodeSequenceError> {
        match self.br.bits_remaining() {
            0 => Ok(()),
            r if r < 0 => Err(DecodeSequenceError::NotEnoughBytesForNumSequences),
            r => Err(DecodeSequenceError::ExtraBits { bits_remaining: r }),
        }
    }
}

fn maybe_update_fse_tables(
    section: &SequencesHeader,
    source: &[u8],
    scratch: &mut FSEScratch,
) -> Result<usize, DecodeSequenceError> {
    let modes = section
        .modes
        .ok_or(DecodeSequenceError::MissingCompressionMode)?;

    let mut bytes_read = 0;

    for (table, mode) in
        scratch
            .seq_tables
            .iter_mut()
            .zip([modes.ll_mode(), modes.ml_mode(), modes.of_mode()])
    {
        if !matches!(mode, ModeType::Repeat) {
            table.stale = true;
        }
    }

    match modes.ll_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.literal_lengths.build_decoder(source, LL_MAX_LOG)?;
            bytes_read += bytes;

            vprintln!("Updating ll table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ll_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ll table");
            if source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleLlTable);
            }
            bytes_read += 1;
            if source[0] > MAX_LITERAL_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ll_rle = Some(source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ll table");
            scratch.literal_lengths.build_from_probabilities(
                LL_DEFAULT_ACC_LOG,
                &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ll_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ll table");
            /* Nothing to do */
        }
    };

    let of_source = &source[bytes_read..];

    match modes.of_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.offsets.build_decoder(of_source, OF_MAX_LOG)?;
            vprintln!("Updating of table");
            vprintln!("Used bytes: {}", bytes);
            bytes_read += bytes;
            scratch.of_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE of table");
            if of_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleOfTable);
            }
            bytes_read += 1;
            if of_source[0] > MAX_OFFSET_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.of_rle = Some(of_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined of table");
            scratch.offsets.build_from_probabilities(
                OF_DEFAULT_ACC_LOG,
                &Vec::from(&OFFSET_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.of_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat of table");
            /* Nothing to do */
        }
    };

    let ml_source = &source[bytes_read..];

    match modes.ml_mode() {
        ModeType::FSECompressed => {
            let bytes = scratch.match_lengths.build_decoder(ml_source, ML_MAX_LOG)?;
            bytes_read += bytes;
            vprintln!("Updating ml table");
            vprintln!("Used bytes: {}", bytes);
            scratch.ml_rle = None;
        }
        ModeType::RLE => {
            vprintln!("Use RLE ml table");
            if ml_source.is_empty() {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            bytes_read += 1;
            if ml_source[0] > MAX_MATCH_LENGTH_CODE {
                return Err(DecodeSequenceError::MissingByteForRleMlTable);
            }
            scratch.ml_rle = Some(ml_source[0]);
        }
        ModeType::Predefined => {
            vprintln!("Use predefined ml table");
            scratch.match_lengths.build_from_probabilities(
                ML_DEFAULT_ACC_LOG,
                &Vec::from(&MATCH_LENGTH_DEFAULT_DISTRIBUTION[..]),
            )?;
            scratch.ml_rle = None;
        }
        ModeType::Repeat => {
            vprintln!("Repeat ml table");
            /* Nothing to do */
        }
    };

    Ok(bytes_read)
}

// The default Literal Length decoding table uses an accuracy logarithm of 6 bits.
const LL_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literals-length
const LITERALS_LENGTH_DEFAULT_DISTRIBUTION: [i32; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 6 bits.
const ML_DEFAULT_ACC_LOG: u8 = 6;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const MATCH_LENGTH_DEFAULT_DISTRIBUTION: [i32; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

// The default Match Length decoding table uses an accuracy logarithm of 5 bits.
const OF_DEFAULT_ACC_LOG: u8 = 5;
/// If [ModeType::Predefined] is selected for a symbol type, its FSE decoding
/// table is generated using a predefined distribution table.
///
/// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
const OFFSET_DEFAULT_DISTRIBUTION: [i32; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

#[test]
fn test_ll_default() {
    let mut table = crate::fse::FSETable::new(MAX_LITERAL_LENGTH_CODE);
    table
        .build_from_probabilities(
            LL_DEFAULT_ACC_LOG,
            &Vec::from(&LITERALS_LENGTH_DEFAULT_DISTRIBUTION[..]),
        )
        .unwrap();

    #[cfg(feature = "std")]
    for idx in 0..table.decode.len() {
        std::println!(
            "{:3}: {:3} {:3} {:3}",
            idx,
            table.decode[idx].symbol,
            table.decode[idx].num_bits,
            table.decode[idx].base_line
        );
    }

    assert!(table.decode.len() == 64);

    //just test a few values. TODO test all values
    assert!(table.decode[0].symbol == 0);
    assert!(table.decode[0].num_bits == 4);
    assert!(table.decode[0].base_line == 0);

    assert!(table.decode[19].symbol == 27);
    assert!(table.decode[19].num_bits == 6);
    assert!(table.decode[19].base_line == 0);

    assert!(table.decode[39].symbol == 25);
    assert!(table.decode[39].num_bits == 4);
    assert!(table.decode[39].base_line == 16);

    assert!(table.decode[60].symbol == 35);
    assert!(table.decode[60].num_bits == 6);
    assert!(table.decode[60].base_line == 0);

    assert!(table.decode[59].symbol == 24);
    assert!(table.decode[59].num_bits == 5);
    assert!(table.decode[59].base_line == 32);
}
