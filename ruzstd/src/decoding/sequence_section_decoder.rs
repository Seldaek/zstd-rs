use super::super::blocks::sequence_section::ModeType;
use super::super::blocks::sequence_section::Sequence;
use super::super::blocks::sequence_section::SequencesHeader;
use super::scratch::{FSEScratch, SeqEntry, SeqTable, SEQ_TABLE_SIZE};
use crate::bit_io::{BitReaderReversed, FastBits};
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

/// The value a literal length code starts at and how many extra bits it reads.
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ll_code(code: u8) -> (u32, u8) {
    const BITS: [u8; 36] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16,
    ];
    const BASE: [u32; 36] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48,
        64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ];
    (BASE[code as usize], BITS[code as usize])
}

/// The value a match length code starts at and how many extra bits it reads.
///
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes>
fn lookup_ml_code(code: u8) -> (u32, u8) {
    const BITS: [u8; 53] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    const BASE: [u32; 53] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
        1027, 2051, 4099, 8195, 16387, 32771, 65539,
    ];
    (BASE[code as usize], BITS[code as usize])
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
    if let Some(code) = rle {
        // a single state that reads no bits
        let (value, extra_bits) = lookup(code);
        out.entries[0] = SeqEntry {
            base_line: 0,
            value,
            num_bits: 0,
            extra_bits,
        };
        out.accuracy_log = 0;
        return Ok(());
    }
    if fse.accuracy_log == 0 {
        return Err(FSEDecoderError::TableIsUninitialized.into());
    }
    debug_assert!(fse.decode.len() <= SEQ_TABLE_SIZE);
    for (e, out) in fse.decode.iter().zip(out.entries.iter_mut()) {
        if e.symbol > max_code {
            return Err(DecodeSequenceError::UnsupportedOffset {
                offset_code: e.symbol,
            });
        }
        let (value, extra_bits) = lookup(e.symbol);
        *out = SeqEntry {
            base_line: e.base_line as u16,
            value,
            num_bits: e.num_bits,
            extra_bits,
        };
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
    tables: [&[SeqEntry; SEQ_TABLE_SIZE]; 3],
    last: bool,
) -> Sequence {
    let ll = tables[0][states[0] as usize % SEQ_TABLE_SIZE];
    let ml = tables[1][states[1] as usize % SEQ_TABLE_SIZE];
    let of = tables[2][states[2] as usize % SEQ_TABLE_SIZE];
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
        states[0] = u32::from(ll.base_line) + br.get_bits_unchecked(ll.num_bits) as u32;
        states[1] = u32::from(ml.base_line) + br.get_bits_unchecked(ml.num_bits) as u32;
        states[2] = u32::from(of.base_line) + br.get_bits_unchecked(of.num_bits) as u32;
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
    tables: [&'a [SeqEntry; SEQ_TABLE_SIZE]; 3],
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

    /// Runs `f` on sequences for as long as they can be decoded without checked refills and it returns true,
    /// leaving at least the last one to `next`. Works on copies of the state so it stays in registers.
    #[inline(always)]
    pub(crate) fn for_each_fast(&mut self, mut f: impl FnMut(Sequence) -> bool) {
        let source = self.br.source();
        let Some(mut bits) = FastBits::new(source, 0, &self.br) else {
            return;
        };
        let [ll_table, ml_table, of_table] = self.tables;
        let [mut ll_state, mut ml_state, mut of_state] = self.states;
        let mut remaining = self.remaining;
        // a sequence refills at most twice
        while remaining > 1 && bits.can_refill(0, 2) {
            remaining -= 1;
            bits.refill(source);
            let ll = ll_table[ll_state as usize % SEQ_TABLE_SIZE];
            let ml = ml_table[ml_state as usize % SEQ_TABLE_SIZE];
            let of = of_table[of_state as usize % SEQ_TABLE_SIZE];
            let (ll_extra, ml_extra, of_extra) = (
                u32::from(ll.extra_bits),
                u32::from(ml.extra_bits),
                u32::from(of.extra_bits),
            );
            let (ll_bits, ml_bits, of_bits) = (
                u32::from(ll.num_bits),
                u32::from(ml.num_bits),
                u32::from(of.num_bits),
            );
            let of_add = bits.peek_at(0, of_extra);
            let ml_add = bits.peek_at(of_extra, ml_extra);
            let mut at = of_extra + ml_extra;
            if at + ll_extra > FastBits::AFTER_REFILL - MAX_STATE_BITS as u32 {
                bits.consume(at);
                bits.refill(source);
                at = 0;
            }
            let ll_add = bits.peek_at(at, ll_extra);
            let ll_at = at + ll_extra;
            let ml_at = ll_at + ll_bits;
            let of_at = ml_at + ml_bits;
            ll_state = u32::from(ll.base_line) + bits.peek_at(ll_at, ll_bits) as u32;
            ml_state = u32::from(ml.base_line) + bits.peek_at(ml_at, ml_bits) as u32;
            of_state = u32::from(of.base_line) + bits.peek_at(of_at, of_bits) as u32;
            bits.consume(of_at + of_bits);
            let seq = Sequence {
                ll: ll.value + ll_add as u32,
                ml: ml.value + ml_add as u32,
                of: of.value + of_add as u32,
            };
            if !f(seq) {
                break;
            }
        }
        self.br = bits.into_reader(source, 0);
        self.states = [ll_state, ml_state, of_state];
        self.remaining = remaining;
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
                &LITERALS_LENGTH_DEFAULT_DISTRIBUTION,
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
            scratch
                .offsets
                .build_from_probabilities(OF_DEFAULT_ACC_LOG, &OFFSET_DEFAULT_DISTRIBUTION)?;
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
            scratch
                .match_lengths
                .build_from_probabilities(ML_DEFAULT_ACC_LOG, &MATCH_LENGTH_DEFAULT_DISTRIBUTION)?;
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
        .build_from_probabilities(LL_DEFAULT_ACC_LOG, &LITERALS_LENGTH_DEFAULT_DISTRIBUTION)
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
