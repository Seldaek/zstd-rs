use core::convert::{TryFrom, TryInto};

/// Zstandard encodes some types of data in a way that the data must be read
/// back to front to decode it properly. `BitReaderReversed` provides a
/// convenient interface to do that.
pub struct BitReaderReversed<'s> {
    /// The index of the last read byte in the source.
    index: usize,

    /// How many bits have been consumed from `bit_container`.
    bits_consumed: u8,

    /// How many bits have been consumed past the end of the input. Will be zero until all the input
    /// has been read.
    extra_bits: usize,

    /// The source data to read from.
    source: &'s [u8],

    /// The reader doesn't read directly from the source, it reads bits from here, and the container
    /// is "refilled" as it's emptied.
    bit_container: u64,
}

impl<'s> BitReaderReversed<'s> {
    /// How many bits are left to read by the reader.
    pub fn bits_remaining(&self) -> isize {
        self.index as isize * 8 + (64 - self.bits_consumed as isize) - self.extra_bits as isize
    }

    /// How many bytes are definitely still unread in the stream
    #[inline(always)]
    pub fn byte_idx(&self) -> usize {
        self.index
    }

    /// The data this reads from.
    pub fn source(&self) -> &'s [u8] {
        self.source
    }

    pub fn new(source: &'s [u8]) -> BitReaderReversed<'s> {
        BitReaderReversed {
            index: source.len(),
            bits_consumed: 64,
            source,
            bit_container: 0,
            extra_bits: 0,
        }
    }

    /// This assumes that the stream still has enough bytes left to just adjust the bit_container down by the bytes consumed in the container
    #[inline(always)]
    pub fn refill_unchecked(&mut self) {
        let bytes_consumed = self.bits_consumed as usize / 8;
        // If the reader wasn't byte aligned, the byte that was partially read is now in the highest order bits in the `bit_container`
        self.index -= bytes_consumed;
        // Some bits of the `bits_container` might have been consumed already because we read the window byte aligned
        self.bits_consumed &= 7;
        // This actually benchmarks faster than the unsafe variant:
        // self.bit_container = unsafe { self.source.as_ptr().add(self.index).cast::<u64>().read_unaligned() };
        self.bit_container = u64::from_le_bytes(
            (&self.source[self.index..self.index + 8])
                .try_into()
                .unwrap(),
        );
    }

    /// We refill the container in full bytes, shifting the still unread portion to the left, and filling the lower bits with new data
    /// This ensures that at least 56 bits are readable before a new refill is necessary
    #[cold]
    pub fn refill(&mut self) {
        let bytes_consumed = self.bits_consumed as usize / 8;
        if bytes_consumed == 0 {
            return;
        }

        if self.index >= bytes_consumed {
            // We can safely move the window contained in `bit_container` down by `bytes_consumed`
            self.refill_unchecked();
        } else if self.index > 0 {
            // Read the last portion of source into the `bit_container`
            if self.source.len() >= 8 {
                self.bit_container = u64::from_le_bytes((&self.source[..8]).try_into().unwrap());
            } else {
                let mut value = [0; 8];
                value[..self.source.len()].copy_from_slice(self.source);
                self.bit_container = u64::from_le_bytes(value);
            }

            self.bits_consumed -= 8 * self.index as u8;
            self.index = 0;

            self.bit_container <<= self.bits_consumed;
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
        } else if self.bits_consumed < 64 {
            // Shift out already used bits and fill up with zeroes
            self.bit_container <<= self.bits_consumed;
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
        } else {
            // All useful bits have already been read and more than 64 bits have been consumed, all we now do is return zeroes
            self.extra_bits += self.bits_consumed as usize;
            self.bits_consumed = 0;
            self.bit_container = 0;
        }

        // Assert that at least `56 = 64 - 8` bits are available to read.
        debug_assert!(self.bits_consumed < 8);
    }

    /// Read `n` number of bits from the source. Will read at most 56 bits.
    /// If there are no more bits to be read from the source zero bits will be returned instead.
    #[inline(always)]
    pub fn get_bits(&mut self, n: u8) -> u64 {
        if self.bits_consumed + n > 64 {
            self.refill();
        }

        let value = self.peek_bits(n);
        self.consume(n);
        value
    }

    /// Get the next `n` bits from the source without consuming them.
    /// Caller is responsible for making sure that `n` many bits have been refilled.
    #[inline(always)]
    pub fn peek_bits(&mut self, n: u8) -> u64 {
        if n == 0 {
            return 0;
        }

        let mask = (1u64 << n) - 1u64;
        let shift_by = 64 - self.bits_consumed - n;
        (self.bit_container >> shift_by) & mask
    }

    /// Consume `n` bits from the source.
    #[inline(always)]
    pub fn consume(&mut self, n: u8) {
        self.bits_consumed += n;
        debug_assert!(self.bits_consumed <= 64);
    }

    /// Peeks at the next `n` bits, which the caller must have refilled. Branchless, also for `n == 0`.
    #[inline(always)]
    pub fn peek_bits_unchecked(&self, n: u8) -> u64 {
        debug_assert!(self.bits_consumed + n <= 64);
        self.bit_container
            .wrapping_shr(u32::from(64 - self.bits_consumed - n))
            & ((1u64 << n) - 1)
    }

    /// Reads `n` bits, which the caller must have refilled. Branchless, also for `n == 0`.
    #[inline(always)]
    pub fn get_bits_unchecked(&mut self, n: u8) -> u64 {
        debug_assert!(self.bits_consumed + n <= 64);
        let value = self
            .bit_container
            .wrapping_shr(u32::from(64 - self.bits_consumed - n))
            & ((1u64 << n) - 1);
        self.bits_consumed += n;
        value
    }
}

/// Reads a bitstream like [BitReaderReversed], for the part that is far enough from its start for unchecked
/// refills.
///
/// The unread bits are kept at the top of `buf`, and a refill ors in the bytes before `pos` below them. The
/// position of that read only depends on the previous refill, so unlike reloading the whole container,
/// it does not wait for the bits consumed since to be known. The stream is `source[start..]`, where
/// several readers can share one `source`.
pub(crate) struct FastBits {
    /// Bytes of `source` before this are not in `buf` yet.
    pos: usize,
    buf: u64,
    /// Valid bits in `buf`. Below them are the next bits of the stream already, or zeroes.
    count: u32,
}

impl FastBits {
    /// At least this many bits are valid after a refill.
    pub(crate) const AFTER_REFILL: u32 = 56;

    /// Takes over from `br`, which reads a stream starting at `source[start]`. None if the stream is too
    /// short for a refill, or was read past its start.
    #[inline(always)]
    pub(crate) fn new(source: &[u8], start: usize, br: &BitReaderReversed<'_>) -> Option<Self> {
        let unread = usize::try_from(br.bits_remaining()).ok()?;
        let bytes = unread.div_ceil(8);
        if bytes < 8 || start + bytes > source.len() {
            return None;
        }
        let mut bits = FastBits {
            pos: start + bytes,
            buf: 0,
            count: 0,
        };
        bits.refill(source);
        // the bits of the last byte that were read already
        bits.consume((bytes * 8 - unread) as u32);
        Some(bits)
    }

    /// How many times this can refill without reading before `start`: a refill reads the 8 bytes before
    /// `pos` and moves it by at most 7.
    #[inline(always)]
    pub(crate) fn refills_from(&self, start: usize) -> usize {
        (self.pos - start).saturating_sub(1) / 7
    }

    /// Whether `refills_from(start) >= times`.
    #[inline(always)]
    pub(crate) fn can_refill(&self, start: usize, times: usize) -> bool {
        self.pos - start > 7 * times
    }

    #[inline(always)]
    pub(crate) fn refill(&mut self, source: &[u8]) {
        let word = u64::from_le_bytes(source[self.pos - 8..self.pos].try_into().unwrap());
        self.buf |= word >> self.count;
        self.pos -= ((63 - self.count) >> 3) as usize;
        self.count |= 56;
    }

    /// The `n` bits found after skipping `skip` bits. Branchless, also for `n == 0`.
    #[inline(always)]
    pub(crate) fn peek_at(&self, skip: u32, n: u32) -> u64 {
        debug_assert!(skip + n <= self.count && n < 64);
        ((self.buf << skip) >> 1) >> (63 - n)
    }

    /// The next `64 - shift` bits, at least one.
    #[inline(always)]
    pub(crate) fn peek_top(&self, shift: u32) -> u64 {
        self.buf >> shift
    }

    #[inline(always)]
    pub(crate) fn consume(&mut self, n: u32) {
        self.buf <<= n;
        self.count -= n;
    }

    /// A reader positioned on the same bit of the stream starting at `source[start]`.
    #[inline(always)]
    pub(crate) fn into_reader(self, source: &[u8], start: usize) -> BitReaderReversed<'_> {
        let unread = (self.pos - start) * 8 + self.count as usize;
        let bytes = unread.div_ceil(8);
        let mut br = BitReaderReversed::new(&source[start..start + bytes]);
        br.get_bits((bytes * 8 - unread) as u8);
        br
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn it_works() {
        let data = [0b10101010, 0b01010101];
        let mut br = super::BitReaderReversed::new(&data);
        assert_eq!(br.get_bits(1), 0);
        assert_eq!(br.get_bits(1), 1);
        assert_eq!(br.get_bits(1), 0);
        assert_eq!(br.get_bits(4), 0b1010);
        assert_eq!(br.get_bits(4), 0b1101);
        assert_eq!(br.get_bits(4), 0b0101);
        // Last 0 from source, three zeroes filled in
        assert_eq!(br.get_bits(4), 0b0000);
        // All zeroes filled in
        assert_eq!(br.get_bits(4), 0b0000);
        assert_eq!(br.bits_remaining(), -7);
    }
}
