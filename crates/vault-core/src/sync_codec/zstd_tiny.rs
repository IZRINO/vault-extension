//! Compact, zero-dependency RFC 8878 Zstandard frame compressor & decompressor
//! tailored for `vault-core` WASM size budget (`<= 250 KB`).
//!
//! - Emits 100% standard RFC 8878 Zstandard frames (`0xFD2FB528` magic) decodable by `libzstd`.
//! - Decodes full RFC 8878 Zstandard frames (Raw/RLE/Compressed blocks, Raw/RLE/Huff0 1x&4x literals,
//!   Predefined/RLE/FSE/Repeat sequence tables, and sliding-window backreferences).

use std::sync::OnceLock;

use zeroize::Zeroize;

use crate::error::VaultError;
use crate::json_lite::compact_sort_by;

const ZSTD_MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MAGIC_LOW: u32 = 0x184D_2A50;
const SKIPPABLE_MAGIC_HIGH: u32 = 0x184D_2A5F;
const MAX_BLOCK_SIZE: usize = 128 * 1024;
const MAX_HUFF_BITS: u8 = 11;

const LL_DEFAULT_ACC_LOG: u8 = 6;
const LL_DEFAULT_DIST: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];

const ML_DEFAULT_ACC_LOG: u8 = 6;
const ML_DEFAULT_DIST: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

const OF_DEFAULT_ACC_LOG: u8 = 5;
const OF_DEFAULT_DIST: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

#[inline(never)]
fn zstd_err() -> VaultError {
    VaultError::CodecError("zstd stream error".into())
}

#[inline]
fn highest_bit_set(x: u32) -> u32 {
    u32::BITS - x.leading_zeros()
}

#[inline]
fn fse_next_pos(p: usize, table_size: usize) -> usize {
    (p + (table_size >> 1) + (table_size >> 3) + 3) & (table_size - 1)
}

// ============================================================================
// Bit I/O Primitives
// ============================================================================

struct ForwardBitReader<'a> {
    src: &'a [u8],
    bit_pos: usize,
}

impl<'a> ForwardBitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, bit_pos: 0 }
    }

    fn read_bits(&mut self, n: usize) -> Result<u32, VaultError> {
        if n == 0 {
            return Ok(0);
        }
        let max_lookahead = (self.src.len() + 1) * 8;
        if self.bit_pos + n > max_lookahead {
            return Err(zstd_err());
        }
        let byte_idx = self.bit_pos >> 3;
        let bit_off = self.bit_pos & 7;
        let mut buf = [0u8; 8];
        let avail = self.src.len().saturating_sub(byte_idx).min(8);
        buf[..avail].copy_from_slice(&self.src[byte_idx..byte_idx + avail]);
        let word = u64::from_le_bytes(buf);
        self.bit_pos += n;
        let mask = if n == 32 { u64::MAX } else { (1u64 << n) - 1 };
        Ok(((word >> bit_off) & mask) as u32)
    }

    fn rewind_bits(&mut self, n: usize) {
        self.bit_pos = self.bit_pos.saturating_sub(n);
    }

    fn bytes_consumed(&self) -> Result<usize, VaultError> {
        if self.bit_pos > self.src.len() * 8 {
            return Err(zstd_err());
        }
        Ok((self.bit_pos + 7) >> 3)
    }
}

struct ReverseBitReader<'a> {
    src: &'a [u8],
    cursor: isize,
}

impl<'a> ReverseBitReader<'a> {
    fn new(src: &'a [u8]) -> Result<Self, VaultError> {
        let Some(&last) = src.last() else {
            return Err(zstd_err());
        };
        if last == 0 {
            return Err(zstd_err());
        }
        let padding = 1 + (last.leading_zeros() as isize);
        let total_bits = (src.len() as isize) * 8 - padding;
        Ok(Self {
            src,
            cursor: total_bits,
        })
    }

    #[inline]
    fn bits_remaining(&self) -> isize {
        self.cursor
    }

    #[inline]
    fn get_bits(&mut self, n: u8) -> u32 {
        if n == 0 {
            return 0;
        }
        let hi = self.cursor;
        let lo = hi - (n as isize);
        self.cursor = lo;
        if hi <= 0 {
            return 0;
        }
        if lo >= 0 {
            let byte_idx = (lo as usize) >> 3;
            let bit_off = (lo as usize) & 7;
            let mut buf = [0u8; 8];
            let avail = (self.src.len() - byte_idx).min(8);
            buf[..avail].copy_from_slice(&self.src[byte_idx..byte_idx + avail]);
            let word = u64::from_le_bytes(buf);
            let mask = if n == 32 { u32::MAX as u64 } else { (1u64 << n) - 1 };
            ((word >> bit_off) & mask) as u32
        } else {
            let avail_bits = hi as u8;
            let zero_pad = (-lo) as u8;
            let mut buf = [0u8; 8];
            let avail = self.src.len().min(8);
            buf[..avail].copy_from_slice(&self.src[..avail]);
            let word = u64::from_le_bytes(buf);
            let mask = (1u64 << avail_bits) - 1;
            ((word & mask) as u32) << zero_pad
        }
    }
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    partial: u64,
    bits: usize,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            partial: 0,
            bits: 0,
        }
    }

    #[inline]
    fn write_bits(&mut self, val: u32, num_bits: usize) {
        if num_bits == 0 {
            return;
        }
        let mask = if num_bits == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << num_bits) - 1
        };
        self.partial |= (u64::from(val) & mask) << self.bits;
        self.bits += num_bits;
        while self.bits >= 8 {
            self.out.push(self.partial as u8);
            self.partial >>= 8;
            self.bits -= 8;
        }
    }

    fn finish_with_sentinel(&mut self) {
        // Sentinel `1` bit + zero padding to complete final byte
        self.write_bits(1, 1);
        if self.bits > 0 {
            self.out.push(self.partial as u8);
            self.partial = 0;
            self.bits = 0;
        }
    }
}

// ============================================================================
// Length & Offset Code Tables (RFC 8878 Appendix A)
// ============================================================================

#[inline]
fn lookup_ll_code(code: u8) -> Result<(u32, u8), VaultError> {
    Ok(match code {
        0..=15 => (u32::from(code), 0),
        16..=19 => (16 + u32::from(code - 16) * 2, 1),
        20..=21 => (24 + u32::from(code - 20) * 4, 2),
        22..=23 => (32 + u32::from(code - 22) * 8, 3),
        24 => (48, 4),
        25 => (64, 6),
        26..=35 => {
            let bits = code - 19;
            (1u32 << bits, bits)
        }
        _ => return Err(zstd_err()),
    })
}

#[inline]
fn encode_ll(len: u32) -> (u8, u32, usize) {
    match len {
        0..=15 => (len as u8, 0, 0),
        16..=23 => {
            let c = 16 + ((len - 16) >> 1) as u8;
            (c, (len - 16) & 1, 1)
        }
        24..=31 => {
            let c = 20 + ((len - 24) >> 2) as u8;
            (c, (len - 24) & 3, 2)
        }
        32..=47 => {
            let c = 22 + ((len - 32) >> 3) as u8;
            (c, (len - 32) & 7, 3)
        }
        48..=63 => (24, len - 48, 4),
        64..=127 => (25, len - 64, 6),
        _ => {
            let bits = len.ilog2() as usize; // 7..=16 for 128..=131071
            let code = (bits + 19) as u8;
            (code, len - (1u32 << bits), bits)
        }
    }
}

#[inline]
fn lookup_ml_code(code: u8) -> Result<(u32, u8), VaultError> {
    Ok(match code {
        0..=31 => (u32::from(code) + 3, 0),
        32..=35 => (35 + u32::from(code - 32) * 2, 1),
        36..=37 => (43 + u32::from(code - 36) * 4, 2),
        38..=39 => (51 + u32::from(code - 38) * 8, 3),
        40..=41 => (67 + u32::from(code - 40) * 16, 4),
        42 => (99, 5),
        43..=52 => {
            let bits = code - 36;
            ((1u32 << bits) + 3, bits)
        }
        _ => return Err(zstd_err()),
    })
}

#[inline]
fn encode_ml(len: u32) -> (u8, u32, usize) {
    match len {
        3..=34 => ((len - 3) as u8, 0, 0),
        35..=42 => {
            let c = 32 + ((len - 35) >> 1) as u8;
            (c, (len - 35) & 1, 1)
        }
        43..=50 => {
            let c = 36 + ((len - 43) >> 2) as u8;
            (c, (len - 43) & 3, 2)
        }
        51..=66 => {
            let c = 38 + ((len - 51) >> 3) as u8;
            (c, (len - 51) & 7, 3)
        }
        67..=98 => {
            let c = 40 + ((len - 67) >> 4) as u8;
            (c, (len - 67) & 15, 4)
        }
        99..=130 => (42, len - 99, 5),
        _ => {
            let adj = len - 3;
            let bits = adj.ilog2() as usize; // 7..=16
            let code = (bits + 36) as u8;
            (code, adj - (1u32 << bits), bits)
        }
    }
}

#[inline]
fn encode_of(of_val: u32) -> (u8, u32, usize) {
    let log = of_val.ilog2() as usize;
    (log as u8, of_val & ((1u32 << log) - 1), log)
}

// ============================================================================
// FSE Decoding & Predefined Encoding Tables
// ============================================================================

#[derive(Clone, Copy, Default)]
struct FseDecodeEntry {
    baseline: u16,
    num_bits: u8,
    symbol: u8,
}

#[derive(Clone, Default)]
struct FseDecodeTable {
    acc_log: u8,
    entries: Vec<FseDecodeEntry>,
    rle_symbol: Option<u8>,
}

impl FseDecodeTable {
    fn from_rle(sym: u8) -> Self {
        Self {
            acc_log: 0,
            entries: Vec::new(),
            rle_symbol: Some(sym),
        }
    }

    fn from_probs(acc_log: u8, probs: &[i16], max_symbol: u8) -> Result<Self, VaultError> {
        if acc_log == 0 || probs.len() > (max_symbol as usize) + 1 {
            return Err(zstd_err());
        }
        let table_size = 1usize << acc_log;
        let mut entries = vec![FseDecodeEntry::default(); table_size];
        let mut neg_idx = table_size;

        for (sym, &p) in probs.iter().enumerate() {
            if p == -1 {
                if neg_idx == 0 {
                    return Err(zstd_err());
                }
                neg_idx -= 1;
                entries[neg_idx] = FseDecodeEntry {
                    baseline: 0,
                    num_bits: acc_log,
                    symbol: sym as u8,
                };
            }
        }

        let mut pos = 0usize;
        for (sym, &p) in probs.iter().enumerate() {
            if p <= 0 {
                continue;
            }
            for _ in 0..(p as usize) {
                if pos >= neg_idx {
                    return Err(zstd_err());
                }
                entries[pos].symbol = sym as u8;
                pos = fse_next_pos(pos, table_size);
                while pos >= neg_idx {
                    pos = fse_next_pos(pos, table_size);
                }
            }
        }

        let mut counts = vec![0u32; probs.len()];
        for entry in entries.iter_mut().take(neg_idx) {
            let s = entry.symbol as usize;
            let p = probs[s] as u32;
            let c = counts[s];
            counts[s] = c + 1;

            let slices = if p.is_power_of_two() {
                p
            } else {
                1u32 << highest_bit_set(p)
            };
            let double_slices = slices - p;
            let single_slices = p - double_slices;
            let slice_width = (table_size as u32) / slices;
            let nb = (highest_bit_set(slice_width) - 1) as u8;
            if c < double_slices {
                entry.baseline =
                    (single_slices * slice_width + c * slice_width * 2) as u16;
                entry.num_bits = nb + 1;
            } else {
                entry.baseline = ((c - double_slices) * slice_width) as u16;
                entry.num_bits = nb;
            }
        }

        Ok(Self {
            acc_log,
            entries,
            rle_symbol: None,
        })
    }

    fn parse(src: &[u8], max_log: u8, max_symbol: u8) -> Result<(Self, usize), VaultError> {
        let mut br = ForwardBitReader::new(src);
        let acc_log = (br.read_bits(4)? as u8) + 5;
        if acc_log > max_log {
            return Err(zstd_err());
        }
        let prob_sum = 1u32 << acc_log;
        let mut counter = 0u32;
        let mut probs: Vec<i16> = Vec::with_capacity((max_symbol as usize) + 1);

        while counter < prob_sum {
            let max_rem = prob_sum - counter + 1;
            let bits = highest_bit_set(max_rem) as usize;
            let raw = br.read_bits(bits)?;
            let low_thresh = ((1u32 << bits) - 1) - max_rem;
            let mask = (1u32 << (bits - 1)) - 1;
            let small = raw & mask;
            let val = if small < low_thresh {
                br.rewind_bits(1);
                small
            } else if raw > mask {
                raw - low_thresh
            } else {
                raw
            };
            let prob = (val as i16) - 1;
            probs.push(prob);
            if prob != 0 {
                counter += if prob > 0 { prob as u32 } else { 1 };
            } else {
                loop {
                    let skip = br.read_bits(2)? as usize;
                    probs.resize(probs.len() + skip, 0);
                    if skip != 3 {
                        break;
                    }
                }
            }
            if probs.len() > (max_symbol as usize) + 1 {
                return Err(zstd_err());
            }
        }
        if counter != prob_sum {
            return Err(zstd_err());
        }
        let used = br.bytes_consumed()?;
        let tbl = Self::from_probs(acc_log, &probs, max_symbol)?;
        Ok((tbl, used))
    }
}

struct FseState<'a> {
    tbl: &'a FseDecodeTable,
    idx: usize,
}

impl<'a> FseState<'a> {
    fn init(tbl: &'a FseDecodeTable, br: &mut ReverseBitReader<'_>) -> Result<Self, VaultError> {
        if tbl.rle_symbol.is_some() {
            return Ok(Self { tbl, idx: 0 });
        }
        if tbl.entries.is_empty() {
            return Err(zstd_err());
        }
        let idx = br.get_bits(tbl.acc_log) as usize;
        Ok(Self { tbl, idx })
    }

    #[inline]
    fn symbol(&self) -> u8 {
        if let Some(s) = self.tbl.rle_symbol {
            s
        } else {
            self.tbl.entries[self.idx].symbol
        }
    }

    #[inline]
    fn update(&mut self, br: &mut ReverseBitReader<'_>) {
        if self.tbl.rle_symbol.is_none() {
            let e = self.tbl.entries[self.idx];
            let add = br.get_bits(e.num_bits) as usize;
            self.idx = (e.baseline as usize) + add;
        }
    }
}

#[derive(Clone, Copy)]
struct EncState {
    num_bits: u8,
    baseline: u16,
    last_index: u16,
    index: u16,
}

struct FsePredefinedEncTable {
    acc_log: u8,
    table_size: usize,
    symbols: Vec<Vec<EncState>>,
}

impl FsePredefinedEncTable {
    fn build(acc_log: u8, probs: &[i16]) -> Self {
        let table_size = 1usize << acc_log;
        let mut symbols: Vec<Vec<EncState>> = vec![Vec::new(); probs.len()];
        let mut neg_idx = table_size - 1;

        for (sym, &p) in probs.iter().enumerate() {
            if p == -1 {
                symbols[sym].push(EncState {
                    num_bits: acc_log,
                    baseline: 0,
                    last_index: (table_size - 1) as u16,
                    index: neg_idx as u16,
                });
                neg_idx = neg_idx.saturating_sub(1);
            }
        }

        let mut pos = 0usize;
        for (sym, &p) in probs.iter().enumerate() {
            if p <= 0 {
                continue;
            }
            for _ in 0..(p as usize) {
                symbols[sym].push(EncState {
                    num_bits: 0,
                    baseline: 0,
                    last_index: 0,
                    index: pos as u16,
                });
                pos = fse_next_pos(pos, table_size);
                while pos > neg_idx {
                    pos = fse_next_pos(pos, table_size);
                }
            }
        }

        for (sym, &p) in probs.iter().enumerate() {
            if p <= 0 {
                continue;
            }
            let p_u32 = p as u32;
            let st_list = &mut symbols[sym];
            compact_sort_by(st_list, |a, b| a.index.cmp(&b.index));
            let prob_log = if p_u32.is_power_of_two() {
                p_u32.ilog2()
            } else {
                p_u32.ilog2() + 1
            };
            let rounded = 1u32 << prob_log;
            let double_states = rounded - p_u32;
            let single_states = p_u32 - double_states;
            let nb = acc_log - (prob_log as u8);
            let mut baseline = ((single_states as usize) * (1usize << nb)) % table_size;
            for (i, st) in st_list.iter_mut().enumerate() {
                let cur_nb = if (i as u32) < double_states { nb + 1 } else { nb };
                st.num_bits = cur_nb;
                st.baseline = baseline as u16;
                st.last_index = (baseline + (1usize << cur_nb) - 1) as u16;
                baseline = (baseline + (1usize << cur_nb)) % table_size;
            }
            compact_sort_by(st_list, |a, b| a.baseline.cmp(&b.baseline));
        }

        Self {
            acc_log,
            table_size,
            symbols,
        }
    }

    #[inline]
    fn start_state(&self, sym: u8) -> EncState {
        self.symbols[sym as usize][0]
    }

    #[inline]
    fn next_state(&self, sym: u8, state_idx: u16) -> EncState {
        let list = &self.symbols[sym as usize];
        let hint = ((state_idx as usize) * list.len()) / self.table_size;
        for &st in &list[hint..] {
            if st.baseline <= state_idx && state_idx <= st.last_index {
                return st;
            }
        }
        list.iter()
            .copied()
            .find(|st| st.baseline <= state_idx && state_idx <= st.last_index)
            .unwrap_or(list[0])
    }
}

struct PredefinedEncoderTables {
    ll: FsePredefinedEncTable,
    of: FsePredefinedEncTable,
    ml: FsePredefinedEncTable,
}

static PREDEFINED_ENC: OnceLock<PredefinedEncoderTables> = OnceLock::new();

fn predefined_enc() -> &'static PredefinedEncoderTables {
    PREDEFINED_ENC.get_or_init(|| PredefinedEncoderTables {
        ll: FsePredefinedEncTable::build(LL_DEFAULT_ACC_LOG, &LL_DEFAULT_DIST),
        of: FsePredefinedEncTable::build(OF_DEFAULT_ACC_LOG, &OF_DEFAULT_DIST),
        ml: FsePredefinedEncTable::build(ML_DEFAULT_ACC_LOG, &ML_DEFAULT_DIST),
    })
}

// ============================================================================
// Huff0 Literals Decoder (1-stream & 4-stream, FSE & Direct Weights)
// ============================================================================

#[derive(Clone, Copy, Default)]
struct HuffEntry {
    symbol: u8,
    num_bits: u8,
}

#[derive(Default)]
struct HuffDecodeTable {
    max_bits: u8,
    entries: Vec<HuffEntry>,
}

impl HuffDecodeTable {
    fn parse(&mut self, src: &[u8]) -> Result<usize, VaultError> {
        let Some(&header) = src.first() else {
            return Err(zstd_err());
        };
        let mut weights: Vec<u8> = Vec::with_capacity(256);
        let bytes_used = if header < 128 {
            let comp_size = header as usize;
            if src.len() < 1 + comp_size || comp_size == 0 {
                return Err(zstd_err());
            }
            let fse_slice = &src[1..1 + comp_size];
            let (fse_tbl, fse_hdr_len) = FseDecodeTable::parse(fse_slice, 6, 255)?;
            if fse_hdr_len >= comp_size {
                return Err(zstd_err());
            }
            let mut br = ReverseBitReader::new(&fse_slice[fse_hdr_len..])?;
            let mut d1 = FseState::init(&fse_tbl, &mut br)?;
            let mut d2 = FseState::init(&fse_tbl, &mut br)?;
            loop {
                weights.push(d1.symbol());
                d1.update(&mut br);
                if br.bits_remaining() < 0 {
                    weights.push(d2.symbol());
                    break;
                }
                weights.push(d2.symbol());
                d2.update(&mut br);
                if br.bits_remaining() < 0 {
                    weights.push(d1.symbol());
                    break;
                }
                if weights.len() > 255 {
                    return Err(zstd_err());
                }
            }
            1 + comp_size
        } else {
            let num_weights = (header - 127) as usize;
            let needed = num_weights.div_ceil(2);
            if src.len() < 1 + needed {
                return Err(zstd_err());
            }
            for i in 0..num_weights {
                let b = src[1 + (i >> 1)];
                weights.push(if i & 1 == 0 { b >> 4 } else { b & 0x0F });
            }
            1 + needed
        };

        if weights.len() > 255 {
            return Err(zstd_err());
        }
        let mut weight_sum = 0u32;
        for &w in &weights {
            if w > MAX_HUFF_BITS {
                return Err(zstd_err());
            }
            if w > 0 {
                weight_sum += 1u32 << (w - 1);
            }
        }
        if weight_sum == 0 {
            return Err(zstd_err());
        }
        let max_bits = highest_bit_set(weight_sum) as u8;
        if max_bits > MAX_HUFF_BITS {
            return Err(zstd_err());
        }
        let leftover = (1u32 << max_bits).checked_sub(weight_sum).ok_or_else(zstd_err)?;
        if leftover == 0 || !leftover.is_power_of_two() {
            return Err(zstd_err());
        }
        let last_weight = highest_bit_set(leftover) as u8;

        let sym_count = weights.len() + 1;
        let mut sym_bits = vec![0u8; sym_count];
        let mut rank_counts = [0usize; (MAX_HUFF_BITS as usize) + 2];
        for (i, &w) in weights.iter().enumerate() {
            if w > 0 {
                let nb = max_bits + 1 - w;
                sym_bits[i] = nb;
                rank_counts[nb as usize] += 1;
            }
        }
        let last_nb = max_bits + 1 - last_weight;
        sym_bits[weights.len()] = last_nb;
        rank_counts[last_nb as usize] += 1;

        let table_len = 1usize << max_bits;
        self.entries.clear();
        self.entries.resize(table_len, HuffEntry::default());
        self.max_bits = max_bits;

        let mut rank_idx = [0usize; (MAX_HUFF_BITS as usize) + 2];
        for nb in (1..=(max_bits as usize)).rev() {
            rank_idx[nb - 1] = rank_idx[nb] + rank_counts[nb] * (1usize << ((max_bits as usize) - nb));
        }
        if rank_idx[0] != table_len {
            return Err(zstd_err());
        }
        for (sym, &nb) in sym_bits.iter().enumerate() {
            if nb > 0 {
                let base = rank_idx[nb as usize];
                let span = 1usize << (max_bits - nb);
                rank_idx[nb as usize] += span;
                for slot in &mut self.entries[base..base + span] {
                    *slot = HuffEntry {
                        symbol: sym as u8,
                        num_bits: nb,
                    };
                }
            }
        }
        Ok(bytes_used)
    }

    fn decode_stream(&self, stream: &[u8], out: &mut Vec<u8>) -> Result<(), VaultError> {
        if self.max_bits == 0 {
            return Err(zstd_err());
        }
        let mut br = ReverseBitReader::new(stream)?;
        let mask = (1u32 << self.max_bits) - 1;
        let mut state = br.get_bits(self.max_bits);
        let end_mark = -(self.max_bits as isize);
        while br.bits_remaining() > end_mark {
            let e = self.entries[state as usize];
            out.push(e.symbol);
            let add = br.get_bits(e.num_bits);
            state = ((state << e.num_bits) & mask) | add;
        }
        if br.bits_remaining() != end_mark {
            return Err(zstd_err());
        }
        Ok(())
    }
}

// ============================================================================
// Full RFC 8878 Zstandard Decompressor
// ============================================================================

pub fn zstd_decompress_bounded(compressed: &[u8], max_bytes: usize) -> Result<Vec<u8>, VaultError> {
    let mut pos = 0usize;
    let mut out: Vec<u8> = Vec::new();

    if compressed.len() < 4 {
        return Err(zstd_err());
    }

    while pos < compressed.len() {
        if pos + 4 > compressed.len() {
            out.zeroize();
            return Err(zstd_err());
        }
        let magic = u32::from_le_bytes([
            compressed[pos],
            compressed[pos + 1],
            compressed[pos + 2],
            compressed[pos + 3],
        ]);
        pos += 4;

        if (SKIPPABLE_MAGIC_LOW..=SKIPPABLE_MAGIC_HIGH).contains(&magic) {
            if pos + 4 > compressed.len() {
                out.zeroize();
                return Err(zstd_err());
            }
            let skip_len = u32::from_le_bytes([
                compressed[pos],
                compressed[pos + 1],
                compressed[pos + 2],
                compressed[pos + 3],
            ]) as usize;
            pos = pos.checked_add(4 + skip_len).ok_or_else(zstd_err)?;
            if pos > compressed.len() {
                out.zeroize();
                return Err(zstd_err());
            }
            continue;
        }
        if magic != ZSTD_MAGIC || pos >= compressed.len() {
            out.zeroize();
            return Err(zstd_err());
        }

        let fhd = compressed[pos];
        pos += 1;
        if (fhd & 0x08) != 0 {
            out.zeroize();
            return Err(zstd_err()); // reserved bit must be zero
        }
        let single_segment = (fhd & 0x20) != 0;
        let has_checksum = (fhd & 0x04) != 0;
        let dict_id_flag = fhd & 0x03;
        let fcs_flag = fhd >> 6;

        if !single_segment {
            if pos >= compressed.len() {
                out.zeroize();
                return Err(zstd_err());
            }
            pos += 1; // Window_Descriptor
        }

        let dict_bytes = match dict_id_flag {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if pos + dict_bytes > compressed.len() {
            out.zeroize();
            return Err(zstd_err());
        }
        if compressed[pos..pos + dict_bytes].iter().any(|&b| b != 0) {
            out.zeroize();
            return Err(zstd_err()); // external dictionaries not used
        }
        pos += dict_bytes;

        let fcs_bytes = match fcs_flag {
            0 => usize::from(single_segment),
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if pos + fcs_bytes > compressed.len() {
            out.zeroize();
            return Err(zstd_err());
        }
        if fcs_bytes > 0 {
            let mut fcs_buf = [0u8; 8];
            fcs_buf[..fcs_bytes].copy_from_slice(&compressed[pos..pos + fcs_bytes]);
            let mut fcs = u64::from_le_bytes(fcs_buf);
            if fcs_bytes == 2 {
                fcs += 256;
            }
            if fcs <= (max_bytes as u64) && out.is_empty() {
                out.reserve((fcs as usize).min(256 * 1024));
            }
            pos += fcs_bytes;
        }

        let frame_out_start = out.len();
        let mut huff_table = HuffDecodeTable::default();
        let mut ll_table = FseDecodeTable::default();
        let mut of_table = FseDecodeTable::default();
        let mut ml_table = FseDecodeTable::default();
        let mut offset_hist: [usize; 3] = [1, 4, 8];
        let mut literals_buf: Vec<u8> = Vec::new();

        loop {
            if pos + 3 > compressed.len() {
                out.zeroize();
                literals_buf.zeroize();
                return Err(zstd_err());
            }
            let bh = u32::from(compressed[pos])
                | (u32::from(compressed[pos + 1]) << 8)
                | (u32::from(compressed[pos + 2]) << 16);
            pos += 3;
            let last_block = (bh & 1) != 0;
            let block_type = (bh >> 1) & 3;
            let block_size = (bh >> 3) as usize;

            match block_type {
                0 => {
                    // Raw_Block
                    if block_size > MAX_BLOCK_SIZE
                        || pos + block_size > compressed.len()
                        || out.len().saturating_add(block_size) > max_bytes
                    {
                        out.zeroize();
                        literals_buf.zeroize();
                        return Err(zstd_err());
                    }
                    out.extend_from_slice(&compressed[pos..pos + block_size]);
                    pos += block_size;
                }
                1 => {
                    // RLE_Block
                    if block_size > MAX_BLOCK_SIZE
                        || pos >= compressed.len()
                        || out.len().saturating_add(block_size) > max_bytes
                    {
                        out.zeroize();
                        literals_buf.zeroize();
                        return Err(zstd_err());
                    }
                    let byte = compressed[pos];
                    pos += 1;
                    out.resize(out.len() + block_size, byte);
                }
                2 => {
                    // Compressed_Block
                    if block_size > MAX_BLOCK_SIZE || pos + block_size > compressed.len() {
                        out.zeroize();
                        literals_buf.zeroize();
                        return Err(zstd_err());
                    }
                    let block = &compressed[pos..pos + block_size];
                    pos += block_size;
                    if let Err(e) = decode_compressed_block(
                        block,
                        frame_out_start,
                        max_bytes,
                        &mut huff_table,
                        &mut ll_table,
                        &mut of_table,
                        &mut ml_table,
                        &mut offset_hist,
                        &mut literals_buf,
                        &mut out,
                    ) {
                        out.zeroize();
                        literals_buf.zeroize();
                        return Err(e);
                    }
                }
                _ => {
                    out.zeroize();
                    literals_buf.zeroize();
                    return Err(zstd_err());
                }
            }

            if last_block {
                break;
            }
        }
        literals_buf.zeroize();

        if has_checksum {
            if pos + 4 > compressed.len() {
                out.zeroize();
                return Err(zstd_err());
            }
            pos += 4;
        }
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn decode_compressed_block(
    block: &[u8],
    frame_out_start: usize,
    max_bytes: usize,
    huff_table: &mut HuffDecodeTable,
    ll_table: &mut FseDecodeTable,
    of_table: &mut FseDecodeTable,
    ml_table: &mut FseDecodeTable,
    offset_hist: &mut [usize; 3],
    literals_buf: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<(), VaultError> {
    if block.is_empty() {
        return Err(zstd_err());
    }
    let mut bpos = 0usize;
    let lit_b0 = block[0];
    let lit_type = lit_b0 & 3;
    let size_fmt = (lit_b0 >> 2) & 3;

    literals_buf.clear();
    match lit_type {
        0 | 1 => {
            let (regen_size, hdr_len) = match size_fmt {
                0 | 2 => ((lit_b0 >> 3) as usize, 1usize),
                1 => {
                    if block.len() < 2 {
                        return Err(zstd_err());
                    }
                    (((lit_b0 as usize) >> 4) | ((block[1] as usize) << 4), 2usize)
                }
                _ => {
                    if block.len() < 3 {
                        return Err(zstd_err());
                    }
                    (
                        ((lit_b0 as usize) >> 4)
                            | ((block[1] as usize) << 4)
                            | ((block[2] as usize) << 12),
                        3usize,
                    )
                }
            };
            if regen_size > MAX_BLOCK_SIZE {
                return Err(zstd_err());
            }
            bpos += hdr_len;
            if lit_type == 0 {
                if bpos + regen_size > block.len() {
                    return Err(zstd_err());
                }
                literals_buf.extend_from_slice(&block[bpos..bpos + regen_size]);
                bpos += regen_size;
            } else {
                if bpos >= block.len() {
                    return Err(zstd_err());
                }
                literals_buf.resize(regen_size, block[bpos]);
                bpos += 1;
            }
        }
        _ => {
            let (num_streams, regen_size, comp_size, hdr_len) = match size_fmt {
                0 | 1 => {
                    if block.len() < 3 {
                        return Err(zstd_err());
                    }
                    let ns = if size_fmt == 0 { 1usize } else { 4usize };
                    let r = ((lit_b0 as usize) >> 4) | (((block[1] as usize) & 0x3F) << 4);
                    let c = ((block[1] as usize) >> 6) | ((block[2] as usize) << 2);
                    (ns, r, c, 3usize)
                }
                2 => {
                    if block.len() < 4 {
                        return Err(zstd_err());
                    }
                    let r = ((lit_b0 as usize) >> 4)
                        | ((block[1] as usize) << 4)
                        | (((block[2] as usize) & 0x03) << 12);
                    let c = ((block[2] as usize) >> 2) | ((block[3] as usize) << 6);
                    (4usize, r, c, 4usize)
                }
                _ => {
                    if block.len() < 5 {
                        return Err(zstd_err());
                    }
                    let r = ((lit_b0 as usize) >> 4)
                        | ((block[1] as usize) << 4)
                        | (((block[2] as usize) & 0x3F) << 12);
                    let c = ((block[2] as usize) >> 6)
                        | ((block[3] as usize) << 2)
                        | ((block[4] as usize) << 10);
                    (4usize, r, c, 5usize)
                }
            };
            bpos += hdr_len;
            if regen_size > MAX_BLOCK_SIZE || bpos + comp_size > block.len() {
                return Err(zstd_err());
            }
            let mut lslice = &block[bpos..bpos + comp_size];
            bpos += comp_size;
            if lit_type == 2 {
                let tree_bytes = huff_table.parse(lslice)?;
                lslice = &lslice[tree_bytes..];
            } else if huff_table.max_bits == 0 {
                return Err(zstd_err());
            }
            literals_buf.reserve(regen_size);
            if num_streams == 1 {
                huff_table.decode_stream(lslice, literals_buf)?;
            } else {
                if lslice.len() < 6 {
                    return Err(zstd_err());
                }
                let s1 = u16::from_le_bytes([lslice[0], lslice[1]]) as usize;
                let s2 = s1 + (u16::from_le_bytes([lslice[2], lslice[3]]) as usize);
                let s3 = s2 + (u16::from_le_bytes([lslice[4], lslice[5]]) as usize);
                let streams = &lslice[6..];
                if s3 > streams.len() {
                    return Err(zstd_err());
                }
                for sub in [&streams[..s1], &streams[s1..s2], &streams[s2..s3], &streams[s3..]] {
                    huff_table.decode_stream(sub, literals_buf)?;
                }
            }
            if literals_buf.len() != regen_size {
                return Err(zstd_err());
            }
        }
    }

    if bpos >= block.len() {
        return Err(zstd_err());
    }
    let s0 = block[bpos];
    bpos += 1;
    let num_seq = match s0 {
        0 => {
            if bpos != block.len() {
                return Err(zstd_err());
            }
            if out.len().saturating_add(literals_buf.len()) > max_bytes {
                return Err(zstd_err());
            }
            out.extend_from_slice(literals_buf);
            return Ok(());
        }
        1..=127 => s0 as usize,
        128..=254 => {
            if bpos >= block.len() {
                return Err(zstd_err());
            }
            let v = (((s0 as usize) - 128) << 8) + (block[bpos] as usize);
            bpos += 1;
            v
        }
        255 => {
            if bpos + 2 > block.len() {
                return Err(zstd_err());
            }
            let v = (block[bpos] as usize) + ((block[bpos + 1] as usize) << 8) + 0x7F00;
            bpos += 2;
            v
        }
    };

    if bpos >= block.len() {
        return Err(zstd_err());
    }
    let modes = block[bpos];
    bpos += 1;
    if (modes & 3) != 0 {
        return Err(zstd_err());
    }

    bpos += update_seq_table(
        &block[bpos..],
        (modes >> 6) & 3,
        ll_table,
        9,
        35,
        LL_DEFAULT_ACC_LOG,
        &LL_DEFAULT_DIST,
    )?;
    bpos += update_seq_table(
        &block[bpos..],
        (modes >> 4) & 3,
        of_table,
        8,
        31,
        OF_DEFAULT_ACC_LOG,
        &OF_DEFAULT_DIST,
    )?;
    bpos += update_seq_table(
        &block[bpos..],
        (modes >> 2) & 3,
        ml_table,
        9,
        52,
        ML_DEFAULT_ACC_LOG,
        &ML_DEFAULT_DIST,
    )?;

    let mut br = ReverseBitReader::new(&block[bpos..])?;
    let mut ll_st = FseState::init(ll_table, &mut br)?;
    let mut of_st = FseState::init(of_table, &mut br)?;
    let mut ml_st = FseState::init(ml_table, &mut br)?;

    let mut lit_cursor = 0usize;
    let block_out_start = out.len();

    for seq_idx in 0..num_seq {
        let ll_code = ll_st.symbol();
        let ml_code = ml_st.symbol();
        let of_code = of_st.symbol();
        if of_code > 31 {
            return Err(zstd_err());
        }
        let (ll_base, ll_bits) = lookup_ll_code(ll_code)?;
        let (ml_base, ml_bits) = lookup_ml_code(ml_code)?;

        let of_extra = br.get_bits(of_code);
        let ml_extra = br.get_bits(ml_bits);
        let ll_extra = br.get_bits(ll_bits);

        let ll = (ll_base + ll_extra) as usize;
        let ml = (ml_base + ml_extra) as usize;
        let of_val = (1u32 << of_code) + of_extra;

        if seq_idx + 1 < num_seq {
            ll_st.update(&mut br);
            ml_st.update(&mut br);
            of_st.update(&mut br);
        }
        if br.bits_remaining() < 0 {
            return Err(zstd_err());
        }

        if lit_cursor + ll > literals_buf.len() {
            return Err(zstd_err());
        }
        if out.len().saturating_add(ll).saturating_add(ml) > max_bytes {
            return Err(VaultError::InvalidFormat(
                "decompressed zstd stream exceeds safety limit".into(),
            ));
        }
        if ll > 0 {
            out.extend_from_slice(&literals_buf[lit_cursor..lit_cursor + ll]);
            lit_cursor += ll;
        }

        let actual_offset = resolve_offset(of_val as usize, ll > 0, offset_hist);
        let avail_history = out.len() - frame_out_start;
        if actual_offset == 0 || actual_offset > avail_history {
            return Err(zstd_err());
        }
        let copy_start = out.len() - actual_offset;
        if actual_offset >= ml {
            out.extend_from_within(copy_start..copy_start + ml);
        } else {
            out.reserve(ml);
            for i in 0..ml {
                let b = out[copy_start + i];
                out.push(b);
            }
        }
    }

    if br.bits_remaining() != 0 {
        return Err(zstd_err());
    }
    let tail = literals_buf.len() - lit_cursor;
    if tail > 0 {
        if out.len().saturating_add(tail) > max_bytes {
            return Err(VaultError::InvalidFormat(
                "decompressed zstd stream exceeds safety limit".into(),
            ));
        }
        out.extend_from_slice(&literals_buf[lit_cursor..]);
    }
    if out.len() - block_out_start > MAX_BLOCK_SIZE {
        return Err(zstd_err());
    }
    Ok(())
}

fn update_seq_table(
    src: &[u8],
    mode: u8,
    tbl: &mut FseDecodeTable,
    max_log: u8,
    max_sym: u8,
    def_log: u8,
    def_probs: &[i16],
) -> Result<usize, VaultError> {
    match mode {
        0 => {
            *tbl = FseDecodeTable::from_probs(def_log, def_probs, max_sym)?;
            Ok(0)
        }
        1 => {
            let Some(&sym) = src.first() else {
                return Err(zstd_err());
            };
            if sym > max_sym {
                return Err(zstd_err());
            }
            *tbl = FseDecodeTable::from_rle(sym);
            Ok(1)
        }
        2 => {
            let (parsed, used) = FseDecodeTable::parse(src, max_log, max_sym)?;
            *tbl = parsed;
            Ok(used)
        }
        _ => {
            if tbl.rle_symbol.is_none() && tbl.entries.is_empty() {
                return Err(zstd_err());
            }
            Ok(0)
        }
    }
}

#[inline]
fn resolve_offset(of_val: usize, has_literals: bool, hist: &mut [usize; 3]) -> usize {
    let actual = if has_literals {
        match of_val {
            1..=3 => hist[of_val - 1],
            _ => of_val - 3,
        }
    } else {
        match of_val {
            1..=2 => hist[of_val],
            3 => hist[0].saturating_sub(1),
            _ => of_val - 3,
        }
    };
    if has_literals {
        match of_val {
            1 => {}
            2 => {
                hist[1] = hist[0];
                hist[0] = actual;
            }
            _ => {
                hist[2] = hist[1];
                hist[1] = hist[0];
                hist[0] = actual;
            }
        }
    } else if of_val == 1 {
        hist[1] = hist[0];
        hist[0] = actual;
    } else {
        hist[2] = hist[1];
        hist[1] = hist[0];
        hist[0] = actual;
    }
    actual
}

// ============================================================================
// RFC 8878 Zstandard Frame Compressor (LZ77 + Predefined FSE)
// ============================================================================

#[derive(Clone, Copy)]
struct RawSeq {
    ll: u32,
    of_val: u32,
    ml: u32,
}

#[inline]
fn hash4(bytes: &[u8], pos: usize) -> usize {
    let v = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    ((v.wrapping_mul(0x9E37_79B1)) >> 19) as usize // 13-bit (8192 buckets)
}

pub fn zstd_compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + input.len() / 2);
    // Frame Header: Magic + FHD(Single_Segment=1, FCS_Field_Size=4 bytes => 0xA0) + u32 LE content size
    out.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
    out.push(0xA0);
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());

    if input.is_empty() {
        // Single empty Raw_Block with Last_Block=1
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
        return out;
    }

    let mut head_table = vec![u32::MAX; 8192];
    let mut prev_chain = vec![u32::MAX; 65536];
    let mut literals: Vec<u8> = Vec::new();
    let mut seqs: Vec<RawSeq> = Vec::new();
    let mut block_buf: Vec<u8> = Vec::new();

    let mut block_start = 0usize;
    while block_start < input.len() {
        let block_end = (block_start + MAX_BLOCK_SIZE).min(input.len());
        let is_last = block_end == input.len();
        let chunk = &input[block_start..block_end];

        literals.clear();
        seqs.clear();
        block_buf.clear();

        if chunk.len() >= 16 {
            find_matches(
                input,
                block_start,
                block_end,
                &mut head_table,
                &mut prev_chain,
                &mut literals,
                &mut seqs,
            );
        }

        if !seqs.is_empty() {
            encode_compressed_block(&literals, &seqs, &mut block_buf);
        }

        if !block_buf.is_empty() && block_buf.len() < chunk.len() {
            let bh = ((block_buf.len() as u32) << 3) | (2 << 1) | u32::from(is_last);
            out.extend_from_slice(&bh.to_le_bytes()[..3]);
            out.extend_from_slice(&block_buf);
        } else {
            let bh = ((chunk.len() as u32) << 3) | u32::from(is_last);
            out.extend_from_slice(&bh.to_le_bytes()[..3]);
            out.extend_from_slice(chunk);
        }

        block_start = block_end;
    }

    literals.zeroize();
    block_buf.zeroize();
    out
}

fn find_matches(
    input: &[u8],
    block_start: usize,
    block_end: usize,
    head_table: &mut [u32],
    prev_chain: &mut [u32],
    literals: &mut Vec<u8>,
    seqs: &mut Vec<RawSeq>,
) {
    const MAX_WINDOW: usize = 256 * 1024;
    let match_limit = block_end.saturating_sub(4);
    let mut anchor = block_start;
    let mut ip = block_start;

    while ip < match_limit {
        let h = hash4(input, ip);
        let mut cand = head_table[h];
        prev_chain[ip & 0xFFFF] = cand;
        head_table[h] = ip as u32;

        let mut best_len = 3usize;
        let mut best_off = 0usize;
        let mut depth = 0u8;

        while cand != u32::MAX && depth < 12 {
            let cpos = cand as usize;
            let offset = ip - cpos;
            if offset == 0 || offset > MAX_WINDOW {
                break;
            }
            if input[cpos + best_len.min(3)] == input[ip + best_len.min(3)]
                && input[cpos..cpos + 4] == input[ip..ip + 4]
            {
                let max_ml = block_end - ip;
                let mut ml = 4usize;
                while ml < max_ml && input[cpos + ml] == input[ip + ml] {
                    ml += 1;
                }
                if ml > best_len {
                    best_len = ml;
                    best_off = offset;
                    if ml >= 128 {
                        break;
                    }
                }
            }
            if offset >= 65536 {
                break;
            }
            cand = prev_chain[cpos & 0xFFFF];
            depth += 1;
        }

        if best_len >= 4 {
            let ll = ip - anchor;
            literals.extend_from_slice(&input[anchor..ip]);
            seqs.push(RawSeq {
                ll: ll as u32,
                of_val: (best_off as u32) + 3,
                ml: best_len as u32,
            });
            let next_ip = ip + best_len;
            // Seed intermediate hash positions for small/medium matches to improve compression ratio
            let seed_end = next_ip.min(match_limit).min(ip + 32);
            for p in (ip + 1)..seed_end {
                let sh = hash4(input, p);
                prev_chain[p & 0xFFFF] = head_table[sh];
                head_table[sh] = p as u32;
            }
            ip = next_ip;
            anchor = ip;
        } else {
            ip += 1;
        }
    }

    if anchor < block_end {
        literals.extend_from_slice(&input[anchor..block_end]);
    }
}

fn encode_compressed_block(literals: &[u8], seqs: &[RawSeq], out: &mut Vec<u8>) {
    // 1. Raw Literals Section Header + Payload
    let lit_len = literals.len();
    if lit_len < 32 {
        out.push((lit_len as u8) << 3);
    } else if lit_len < 4096 {
        let hdr = ((lit_len as u16) << 4) | 0x04;
        out.extend_from_slice(&hdr.to_le_bytes());
    } else {
        let hdr = ((lit_len as u32) << 4) | 0x0C;
        out.extend_from_slice(&hdr.to_le_bytes()[..3]);
    }
    out.extend_from_slice(literals);

    // 2. Sequences Section Header
    let n = seqs.len();
    if n < 128 {
        out.push(n as u8);
    } else if n < 0x7F00 {
        out.push(((n >> 8) as u8) | 0x80);
        out.push(n as u8);
    } else {
        let rem = (n - 0x7F00) as u16;
        out.push(0xFF);
        out.extend_from_slice(&rem.to_le_bytes());
    }
    // Symbol_Compression_Modes = 0x00 (Predefined for LL, OF, ML)
    out.push(0x00);

    // 3. Backward Predefined FSE Bitstream
    let enc = predefined_enc();
    let mut bw = BitWriter::new(out);

    let last = seqs[n - 1];
    let (ll_c, ll_extra, ll_bits) = encode_ll(last.ll);
    let (of_c, of_extra, of_bits) = encode_of(last.of_val);
    let (ml_c, ml_extra, ml_bits) = encode_ml(last.ml);

    let mut ll_st = enc.ll.start_state(ll_c);
    let mut ml_st = enc.ml.start_state(ml_c);
    let mut of_st = enc.of.start_state(of_c);

    bw.write_bits(ll_extra, ll_bits);
    bw.write_bits(ml_extra, ml_bits);
    bw.write_bits(of_extra, of_bits);

    if n > 1 {
        for &seq in seqs[..n - 1].iter().rev() {
            let (ll_c, ll_extra, ll_bits) = encode_ll(seq.ll);
            let (of_c, of_extra, of_bits) = encode_of(seq.of_val);
            let (ml_c, ml_extra, ml_bits) = encode_ml(seq.ml);

            let next_of = enc.of.next_state(of_c, of_st.index);
            bw.write_bits(u32::from(of_st.index - next_of.baseline), next_of.num_bits as usize);
            of_st = next_of;

            let next_ml = enc.ml.next_state(ml_c, ml_st.index);
            bw.write_bits(u32::from(ml_st.index - next_ml.baseline), next_ml.num_bits as usize);
            ml_st = next_ml;

            let next_ll = enc.ll.next_state(ll_c, ll_st.index);
            bw.write_bits(u32::from(ll_st.index - next_ll.baseline), next_ll.num_bits as usize);
            ll_st = next_ll;

            bw.write_bits(ll_extra, ll_bits);
            bw.write_bits(ml_extra, ml_bits);
            bw.write_bits(of_extra, of_bits);
        }
    }

    bw.write_bits(u32::from(ml_st.index), enc.ml.acc_log as usize);
    bw.write_bits(u32::from(of_st.index), enc.of.acc_log as usize);
    bw.write_bits(u32::from(ll_st.index), enc.ll.acc_log as usize);
    bw.finish_with_sentinel();
}
