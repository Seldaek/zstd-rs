//! Structures that wrap around various decoders to make decoding easier.

use super::super::blocks::sequence_section::Sequence;
use super::decode_buffer::DecodeBuffer;
use crate::decoding::dictionary::Dictionary;
use crate::fse::FSETable;
use crate::huff0::HuffmanTable;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::blocks::sequence_section::{
    MAX_LITERAL_LENGTH_CODE, MAX_MATCH_LENGTH_CODE, MAX_OFFSET_CODE,
};

/// A block level decoding buffer.
pub struct DecoderScratch {
    /// The decoder used for Huffman blocks.
    pub huf: HuffmanScratch,
    /// The decoder used for FSE blocks.
    pub fse: FSEScratch,

    pub buffer: DecodeBuffer,
    pub offset_hist: [u32; 3],

    pub literals_buffer: Vec<u8>,
    pub sequences: Vec<Sequence>,
    pub block_content_buffer: Vec<u8>,
}

impl DecoderScratch {
    pub fn new(window_size: usize) -> DecoderScratch {
        DecoderScratch {
            huf: HuffmanScratch {
                table: HuffmanTable::new(),
            },
            fse: FSEScratch {
                offsets: FSETable::new(MAX_OFFSET_CODE),
                of_rle: None,
                literal_lengths: FSETable::new(MAX_LITERAL_LENGTH_CODE),
                ll_rle: None,
                match_lengths: FSETable::new(MAX_MATCH_LENGTH_CODE),
                ml_rle: None,
                seq_tables: Default::default(),
            },
            buffer: DecodeBuffer::new(window_size),
            offset_hist: [1, 4, 8],

            block_content_buffer: Vec::new(),
            literals_buffer: Vec::new(),
            sequences: Vec::new(),
        }
    }

    pub fn reset(&mut self, window_size: usize) {
        self.offset_hist = [1, 4, 8];
        self.literals_buffer.clear();
        self.sequences.clear();
        self.block_content_buffer.clear();

        self.buffer.reset(window_size);

        self.fse.literal_lengths.reset();
        self.fse.match_lengths.reset();
        self.fse.offsets.reset();
        self.fse.ll_rle = None;
        self.fse.ml_rle = None;
        self.fse.of_rle = None;
        self.fse.seq_tables.stale = [true; 3];

        self.huf.table.reset();
    }

    pub fn init_from_dict(&mut self, dict: &Dictionary) {
        self.fse.reinit_from(&dict.fse);
        self.huf.table.reinit_from(&dict.huf.table);
        self.offset_hist = dict.offset_hist;
        self.buffer.dict_content.clear();
        self.buffer
            .dict_content
            .extend_from_slice(&dict.dict_content);
    }
}

pub struct HuffmanScratch {
    pub table: HuffmanTable,
}

impl HuffmanScratch {
    pub fn new() -> HuffmanScratch {
        HuffmanScratch {
            table: HuffmanTable::new(),
        }
    }
}

impl Default for HuffmanScratch {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FSEScratch {
    pub offsets: FSETable,
    pub of_rle: Option<u8>,
    pub literal_lengths: FSETable,
    pub ll_rle: Option<u8>,
    pub match_lengths: FSETable,
    pub ml_rle: Option<u8>,
    /// The tables above, resolved for decoding sequences (literal lengths, match lengths, offsets).
    pub(crate) seq_tables: SeqTables,
}

/// One FSE state with its symbol resolved to the value and extra bits it stands for.
#[derive(Clone, Copy, Default)]
pub(crate) struct SeqEntry {
    pub value: u32,
    // 8 bytes per entry: states are below `SEQ_TABLES_SIZE`
    pub base_line: u16,
    pub num_bits: u8,
    pub extra_bits: u8,
}

/// The most states a sequence table can have.
pub(crate) const SEQ_TABLE_SIZE: usize = 1 << 9;
/// Room for the three tables, rounded up so that states index it with a mask instead of a bounds check.
pub(crate) const SEQ_TABLES_SIZE: usize = 4 * SEQ_TABLE_SIZE;

/// The literal length, match length and offset tables, one after the other every `SEQ_TABLE_SIZE` entries.
/// States count from the start of `entries`, so that decoding needs a single pointer for the three.
pub(crate) struct SeqTables {
    pub entries: Box<[SeqEntry; SEQ_TABLES_SIZE]>,
    pub accuracy_logs: [u8; 3],
    /// Which need rebuilding from their FSE table or RLE symbol.
    pub stale: [bool; 3],
}

impl Default for SeqTables {
    fn default() -> Self {
        SeqTables {
            entries: Box::new([SeqEntry::default(); SEQ_TABLES_SIZE]),
            accuracy_logs: [0; 3],
            stale: [true; 3],
        }
    }
}

impl FSEScratch {
    pub fn new() -> FSEScratch {
        FSEScratch {
            offsets: FSETable::new(MAX_OFFSET_CODE),
            of_rle: None,
            literal_lengths: FSETable::new(MAX_LITERAL_LENGTH_CODE),
            ll_rle: None,
            match_lengths: FSETable::new(MAX_MATCH_LENGTH_CODE),
            ml_rle: None,
            seq_tables: Default::default(),
        }
    }

    pub fn reinit_from(&mut self, other: &Self) {
        self.offsets.reinit_from(&other.offsets);
        self.literal_lengths.reinit_from(&other.literal_lengths);
        self.match_lengths.reinit_from(&other.match_lengths);
        self.of_rle = other.of_rle;
        self.ll_rle = other.ll_rle;
        self.ml_rle = other.ml_rle;
        self.seq_tables.stale = [true; 3];
    }
}

impl Default for FSEScratch {
    fn default() -> Self {
        Self::new()
    }
}
