//! Kalyna block cipher core (DSTU 7624), ported from Cryptonite `dstu7624.c`.

use crate::error::{Error, Result};

use super::tables::{SUBROWCOL, SUBROWCOL_DEC, S_BLOCKS, S_BLOCKS_REV};

pub const BLOCK_128: usize = 16;
pub const BLOCK_256: usize = 32;
pub const BLOCK_512: usize = 64;

pub const KEY_128: usize = 16;
pub const KEY_256: usize = 32;
pub const KEY_512: usize = 64;

const MAX_RKEY_WORDS: usize = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KalynaVariant {
    K128B128,
    K256B128,
    K256B256,
    K512B256,
    K512B512,
}

/// Kalyna cipher state (S-box 1, precomputed tables from Cryptonite).
pub struct KalynaCore {
    p_boxrowcol: [[u64; 256]; 8],
    p_boxrowcol_rev: [[u64; 256]; 8],
    sbox: [u8; 1024],
    sbox_rev: [u8; 1024],
    p_rkeys: [u64; MAX_RKEY_WORDS],
    p_rkeys_rev: [u64; MAX_RKEY_WORDS],
    block_len: usize,
    key_len: usize,
    rounds: usize,
    variant: KalynaVariant,
}

impl KalynaCore {
    /// Allocate with DSTU7624_SBOX_1 tables (Cryptonite default).
    pub fn new_sbox1() -> Self {
        Self {
            p_boxrowcol: SUBROWCOL,
            p_boxrowcol_rev: SUBROWCOL_DEC,
            sbox: S_BLOCKS,
            sbox_rev: S_BLOCKS_REV,
            p_rkeys: [0; MAX_RKEY_WORDS],
            p_rkeys_rev: [0; MAX_RKEY_WORDS],
            block_len: 0,
            key_len: 0,
            rounds: 0,
            variant: KalynaVariant::K128B128,
        }
    }

    /// Key schedule + parameters from key and block size (bytes).
    pub fn init(&mut self, key: &[u8], block_size: usize) -> Result<()> {
        if !matches!(block_size, BLOCK_128 | BLOCK_256 | BLOCK_512) {
            return Err(Error::InvalidParam("block_size".into()));
        }
        if !matches!(key.len(), KEY_128 | KEY_256 | KEY_512) {
            return Err(Error::InvalidParam("key length".into()));
        }

        let (variant, hrkey0, rounds) = match (key.len(), block_size) {
            (KEY_128, BLOCK_128) => (KalynaVariant::K128B128, 0x05u64, 10),
            (KEY_256, BLOCK_128) => (KalynaVariant::K256B128, 0x07, 14),
            (KEY_256, BLOCK_256) => (KalynaVariant::K256B256, 0x09, 14),
            (KEY_512, BLOCK_256) => (KalynaVariant::K512B256, 0x0D, 18),
            (KEY_512, BLOCK_512) => (KalynaVariant::K512B512, 0x11, 18),
            _ => return Err(Error::InvalidParam("key/block size pair".into())),
        };

        self.key_len = key.len();
        self.block_len = block_size;
        self.rounds = rounds;
        self.variant = variant;
        self.p_rkeys = [0; MAX_RKEY_WORDS];
        self.p_rkeys_rev = [0; MAX_RKEY_WORDS];

        let wblock = block_size / 8;
        let mut hrkey = vec![0u64; wblock];
        hrkey[0] = hrkey0;

        let key_shifts = p_key_shift(key, self.block_len, self.key_len, self.rounds)?;
        p_help_round_key(key, self, &mut hrkey)?;
        precomputed_rkeys(self, &key_shifts, &mut hrkey)?;

        self.p_rkeys_rev = self.p_rkeys;
        reverse_rkey(self);

        Ok(())
    }

    pub fn block_len(&self) -> usize {
        self.block_len
    }

    pub fn encrypt_block(&self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if input.len() != self.block_len || output.len() != self.block_len {
            return Err(Error::InvalidParam("block buffer length".into()));
        }
        let w = self.block_len / 8;
        let mut state = [0u64; 8];
        bytes_to_u64(input, &mut state[..w]);
        self.basic_transform(&mut state[..w]);
        u64_to_bytes(&state[..w], output);
        Ok(())
    }

    pub fn decrypt_block(&self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if input.len() != self.block_len || output.len() != self.block_len {
            return Err(Error::InvalidParam("block buffer length".into()));
        }
        let w = self.block_len / 8;
        let mut state = [0u64; 8];
        bytes_to_u64(input, &mut state[..w]);
        self.decrypt_transform(&mut state[..w]);
        u64_to_bytes(&state[..w], output);
        Ok(())
    }

    /// Forward Kalyna round function on the internal `u64` state (Cryptonite `basic_transform`).
    pub fn basic_transform_state(&self, state: &mut [u64]) {
        self.basic_transform(state);
    }

    fn basic_transform(&self, state: &mut [u64]) {
        match self.variant {
            KalynaVariant::K128B128 => basic_transform_128(self, state),
            KalynaVariant::K256B128 => basic_transform_128_256(self, state),
            KalynaVariant::K256B256 => basic_transform_256(self, state),
            KalynaVariant::K512B256 => basic_transform_256_512(self, state),
            KalynaVariant::K512B512 => basic_transform_512(self, state),
        }
    }

    fn decrypt_transform(&self, state: &mut [u64]) {
        match self.variant {
            KalynaVariant::K128B128 => subrowcol128_dec(self, state),
            KalynaVariant::K256B128 => subrowcol128_256_dec(self, state),
            KalynaVariant::K256B256 => subrowcol256_dec(self, state),
            KalynaVariant::K512B256 => subrowcol256_512_dec(self, state),
            KalynaVariant::K512B512 => subrowcol512_dec(self, state),
        }
    }

    fn subrowcol(&self, state: &mut [u64]) {
        match self.block_len {
            BLOCK_128 => subrowcol128(self, state),
            BLOCK_256 => subrowcol256(self, state),
            BLOCK_512 => subrowcol512(self, state),
            _ => {}
        }
    }
}

fn bytes_to_u64(in_bytes: &[u8], out: &mut [u64]) {
    for (i, chunk) in in_bytes.chunks(8).enumerate() {
        if i >= out.len() {
            break;
        }
        let mut b = [0u8; 8];
        let take = chunk.len().min(8);
        b[..take].copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(b);
    }
}

fn u64_to_bytes(words: &[u64], out: &mut [u8]) {
    let src_len = words.len() * 8;
    let n = out.len().min(src_len);
    for (i, &word) in words.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let off = i * 8;
        if off >= n {
            break;
        }
        let take = (n - off).min(8);
        out[off..off + take].copy_from_slice(&bytes[..take]);
    }
}

fn kalina_add(in_words: &[u64], out: &mut [u64]) {
    for (o, &v) in out.iter_mut().zip(in_words.iter()) {
        *o = o.wrapping_add(v);
    }
}

fn kalina_xor_inplace(state: &mut [u64], key: &[u64]) {
    for i in 0..state.len().min(key.len()) {
        state[i] ^= key[i];
    }
}

fn p_box(t: &[[u64; 256]; 8]) -> &[[u64; 256]; 8] {
    t
}

#[inline]
fn t_at(t: &[[u64; 256]; 8], row: usize, byte: u8) -> u64 {
    t[row][byte as usize]
}

fn bt_xor128(t: &[[u64; 256]; 8], inp: &[u64; 2], out: &mut [u64; 2], rkey: &[u64]) {
    let i0 = inp[0];
    let i1 = inp[1];
    out[0] = t_at(t, 0, i0 as u8)
        ^ t_at(t, 1, (i0 >> 8) as u8)
        ^ t_at(t, 2, (i0 >> 16) as u8)
        ^ t_at(t, 3, (i0 >> 24) as u8)
        ^ t_at(t, 4, (i1 >> 32) as u8)
        ^ t_at(t, 5, (i1 >> 40) as u8)
        ^ t_at(t, 6, (i1 >> 48) as u8)
        ^ t_at(t, 7, (i1 >> 56) as u8)
        ^ rkey[0];
    out[1] = t_at(t, 0, i1 as u8)
        ^ t_at(t, 1, (i1 >> 8) as u8)
        ^ t_at(t, 2, (i1 >> 16) as u8)
        ^ t_at(t, 3, (i1 >> 24) as u8)
        ^ t_at(t, 4, (i0 >> 32) as u8)
        ^ t_at(t, 5, (i0 >> 40) as u8)
        ^ t_at(t, 6, (i0 >> 48) as u8)
        ^ t_at(t, 7, (i0 >> 56) as u8)
        ^ rkey[1];
}

fn bt_add128(t: &[[u64; 256]; 8], inp: &[u64; 2], out: &mut [u64; 2], rkey: &[u64]) {
    let i0 = inp[0];
    let i1 = inp[1];
    out[0] = (t_at(t, 0, i0 as u8)
        ^ t_at(t, 1, (i0 >> 8) as u8)
        ^ t_at(t, 2, (i0 >> 16) as u8)
        ^ t_at(t, 3, (i0 >> 24) as u8)
        ^ t_at(t, 4, (i1 >> 32) as u8)
        ^ t_at(t, 5, (i1 >> 40) as u8)
        ^ t_at(t, 6, (i1 >> 48) as u8)
        ^ t_at(t, 7, (i1 >> 56) as u8))
    .wrapping_add(rkey[0]);
    out[1] = (t_at(t, 0, i1 as u8)
        ^ t_at(t, 1, (i1 >> 8) as u8)
        ^ t_at(t, 2, (i1 >> 16) as u8)
        ^ t_at(t, 3, (i1 >> 24) as u8)
        ^ t_at(t, 4, (i0 >> 32) as u8)
        ^ t_at(t, 5, (i0 >> 40) as u8)
        ^ t_at(t, 6, (i0 >> 48) as u8)
        ^ t_at(t, 7, (i0 >> 56) as u8))
    .wrapping_add(rkey[1]);
}

fn bt_xor256(t: &[[u64; 256]; 8], inp: &[u64; 4], out: &mut [u64; 4], rkey: &[u64]) {
    let (i0, i1, i2, i3) = (inp[0], inp[1], inp[2], inp[3]);
    out[0] = t_at(t, 0, i0 as u8)
        ^ t_at(t, 1, (i0 >> 8) as u8)
        ^ t_at(t, 2, (i3 >> 16) as u8)
        ^ t_at(t, 3, (i3 >> 24) as u8)
        ^ t_at(t, 4, (i2 >> 32) as u8)
        ^ t_at(t, 5, (i2 >> 40) as u8)
        ^ t_at(t, 6, (i1 >> 48) as u8)
        ^ t_at(t, 7, (i1 >> 56) as u8)
        ^ rkey[0];
    out[1] = t_at(t, 0, i1 as u8)
        ^ t_at(t, 1, (i1 >> 8) as u8)
        ^ t_at(t, 2, (i0 >> 16) as u8)
        ^ t_at(t, 3, (i0 >> 24) as u8)
        ^ t_at(t, 4, (i3 >> 32) as u8)
        ^ t_at(t, 5, (i3 >> 40) as u8)
        ^ t_at(t, 6, (i2 >> 48) as u8)
        ^ t_at(t, 7, (i2 >> 56) as u8)
        ^ rkey[1];
    out[2] = t_at(t, 0, i2 as u8)
        ^ t_at(t, 1, (i2 >> 8) as u8)
        ^ t_at(t, 2, (i1 >> 16) as u8)
        ^ t_at(t, 3, (i1 >> 24) as u8)
        ^ t_at(t, 4, (i0 >> 32) as u8)
        ^ t_at(t, 5, (i0 >> 40) as u8)
        ^ t_at(t, 6, (i3 >> 48) as u8)
        ^ t_at(t, 7, (i3 >> 56) as u8)
        ^ rkey[2];
    out[3] = t_at(t, 0, i3 as u8)
        ^ t_at(t, 1, (i3 >> 8) as u8)
        ^ t_at(t, 2, (i2 >> 16) as u8)
        ^ t_at(t, 3, (i2 >> 24) as u8)
        ^ t_at(t, 4, (i1 >> 32) as u8)
        ^ t_at(t, 5, (i1 >> 40) as u8)
        ^ t_at(t, 6, (i0 >> 48) as u8)
        ^ t_at(t, 7, (i0 >> 56) as u8)
        ^ rkey[3];
}

fn bt_add256(t: &[[u64; 256]; 8], inp: &[u64; 4], out: &mut [u64; 4], rkey: &[u64]) {
    let (i0, i1, i2, i3) = (inp[0], inp[1], inp[2], inp[3]);
    out[0] = (t_at(t, 0, i0 as u8)
        ^ t_at(t, 1, (i0 >> 8) as u8)
        ^ t_at(t, 2, (i3 >> 16) as u8)
        ^ t_at(t, 3, (i3 >> 24) as u8)
        ^ t_at(t, 4, (i2 >> 32) as u8)
        ^ t_at(t, 5, (i2 >> 40) as u8)
        ^ t_at(t, 6, (i1 >> 48) as u8)
        ^ t_at(t, 7, (i1 >> 56) as u8))
    .wrapping_add(rkey[0]);
    out[1] = (t_at(t, 0, i1 as u8)
        ^ t_at(t, 1, (i1 >> 8) as u8)
        ^ t_at(t, 2, (i0 >> 16) as u8)
        ^ t_at(t, 3, (i0 >> 24) as u8)
        ^ t_at(t, 4, (i3 >> 32) as u8)
        ^ t_at(t, 5, (i3 >> 40) as u8)
        ^ t_at(t, 6, (i2 >> 48) as u8)
        ^ t_at(t, 7, (i2 >> 56) as u8))
    .wrapping_add(rkey[1]);
    out[2] = (t_at(t, 0, i2 as u8)
        ^ t_at(t, 1, (i2 >> 8) as u8)
        ^ t_at(t, 2, (i1 >> 16) as u8)
        ^ t_at(t, 3, (i1 >> 24) as u8)
        ^ t_at(t, 4, (i0 >> 32) as u8)
        ^ t_at(t, 5, (i0 >> 40) as u8)
        ^ t_at(t, 6, (i3 >> 48) as u8)
        ^ t_at(t, 7, (i3 >> 56) as u8))
    .wrapping_add(rkey[2]);
    out[3] = (t_at(t, 0, i3 as u8)
        ^ t_at(t, 1, (i3 >> 8) as u8)
        ^ t_at(t, 2, (i2 >> 16) as u8)
        ^ t_at(t, 3, (i2 >> 24) as u8)
        ^ t_at(t, 4, (i1 >> 32) as u8)
        ^ t_at(t, 5, (i1 >> 40) as u8)
        ^ t_at(t, 6, (i0 >> 48) as u8)
        ^ t_at(t, 7, (i0 >> 56) as u8))
    .wrapping_add(rkey[3]);
}

macro_rules! bt_xor512_body {
    ($t:expr, $out:expr, $rkey:expr, $o0:expr, $z0:expr, $z1:expr, $z2:expr, $z3:expr, $z4:expr, $z5:expr, $z6:expr, $z7:expr) => {
        $out[$o0] = t_at($t, 0, $z0 as u8)
            ^ t_at($t, 1, ($z1 >> 8) as u8)
            ^ t_at($t, 2, ($z2 >> 16) as u8)
            ^ t_at($t, 3, ($z3 >> 24) as u8)
            ^ t_at($t, 4, ($z4 >> 32) as u8)
            ^ t_at($t, 5, ($z5 >> 40) as u8)
            ^ t_at($t, 6, ($z6 >> 48) as u8)
            ^ t_at($t, 7, ($z7 >> 56) as u8)
            ^ $rkey[$o0];
    };
}

fn bt_xor512(t: &[[u64; 256]; 8], inp: &[u64; 8], out: &mut [u64; 8], rkey: &[u64]) {
    let (i0, i1, i2, i3, i4, i5, i6, i7) = (
        inp[0], inp[1], inp[2], inp[3], inp[4], inp[5], inp[6], inp[7],
    );
    bt_xor512_body!(t, out, rkey, 0, i0, i7, i6, i5, i4, i3, i2, i1);
    bt_xor512_body!(t, out, rkey, 1, i1, i0, i7, i6, i5, i4, i3, i2);
    bt_xor512_body!(t, out, rkey, 2, i2, i1, i0, i7, i6, i5, i4, i3);
    bt_xor512_body!(t, out, rkey, 3, i3, i2, i1, i0, i7, i6, i5, i4);
    bt_xor512_body!(t, out, rkey, 4, i4, i3, i2, i1, i0, i7, i6, i5);
    bt_xor512_body!(t, out, rkey, 5, i5, i4, i3, i2, i1, i0, i7, i6);
    bt_xor512_body!(t, out, rkey, 6, i6, i5, i4, i3, i2, i1, i0, i7);
    bt_xor512_body!(t, out, rkey, 7, i7, i6, i5, i4, i3, i2, i1, i0);
}

fn bt_add512(t: &[[u64; 256]; 8], inp: &[u64; 8], out: &mut [u64; 8], rkey: &[u64]) {
    let mut tmp = [0u64; 8];
    bt_xor512(t, inp, &mut tmp, &[0; 8]);
    for i in 0..8 {
        out[i] = tmp[i].wrapping_add(rkey[i]);
    }
}

fn kalina_g128(t: &[[u64; 256]; 8], inp: &[u64], out: &mut [u64]) {
    out[0] = t[0][(inp[0] & 0xff) as usize]
        ^ t[1][((inp[0] >> 8) & 0xff) as usize]
        ^ t[2][((inp[0] >> 16) & 0xff) as usize]
        ^ t[3][((inp[0] >> 24) & 0xff) as usize]
        ^ t[4][((inp[1] >> 32) & 0xff) as usize]
        ^ t[5][((inp[1] >> 40) & 0xff) as usize]
        ^ t[6][((inp[1] >> 48) & 0xff) as usize]
        ^ t[7][((inp[1] >> 56) & 0xff) as usize];
    out[1] = t[0][(inp[1] & 0xff) as usize]
        ^ t[1][((inp[1] >> 8) & 0xff) as usize]
        ^ t[2][((inp[1] >> 16) & 0xff) as usize]
        ^ t[3][((inp[1] >> 24) & 0xff) as usize]
        ^ t[4][((inp[0] >> 32) & 0xff) as usize]
        ^ t[5][((inp[0] >> 40) & 0xff) as usize]
        ^ t[6][((inp[0] >> 48) & 0xff) as usize]
        ^ t[7][((inp[0] >> 56) & 0xff) as usize];
}

fn kalina_g256(t: &[[u64; 256]; 8], inp: &[u64], out: &mut [u64]) {
    out[0] = t[0][(inp[0] & 0xff) as usize]
        ^ t[1][((inp[0] >> 8) & 0xff) as usize]
        ^ t[2][((inp[3] >> 16) & 0xff) as usize]
        ^ t[3][((inp[3] >> 24) & 0xff) as usize]
        ^ t[4][((inp[2] >> 32) & 0xff) as usize]
        ^ t[5][((inp[2] >> 40) & 0xff) as usize]
        ^ t[6][((inp[1] >> 48) & 0xff) as usize]
        ^ t[7][((inp[1] >> 56) & 0xff) as usize];
    out[1] = t[0][(inp[1] & 0xff) as usize]
        ^ t[1][((inp[1] >> 8) & 0xff) as usize]
        ^ t[2][((inp[0] >> 16) & 0xff) as usize]
        ^ t[3][((inp[0] >> 24) & 0xff) as usize]
        ^ t[4][((inp[3] >> 32) & 0xff) as usize]
        ^ t[5][((inp[3] >> 40) & 0xff) as usize]
        ^ t[6][((inp[2] >> 48) & 0xff) as usize]
        ^ t[7][((inp[2] >> 56) & 0xff) as usize];
    out[2] = t[0][(inp[2] & 0xff) as usize]
        ^ t[1][((inp[2] >> 8) & 0xff) as usize]
        ^ t[2][((inp[1] >> 16) & 0xff) as usize]
        ^ t[3][((inp[1] >> 24) & 0xff) as usize]
        ^ t[4][((inp[0] >> 32) & 0xff) as usize]
        ^ t[5][((inp[0] >> 40) & 0xff) as usize]
        ^ t[6][((inp[3] >> 48) & 0xff) as usize]
        ^ t[7][((inp[3] >> 56) & 0xff) as usize];
    out[3] = t[0][(inp[3] & 0xff) as usize]
        ^ t[1][((inp[3] >> 8) & 0xff) as usize]
        ^ t[2][((inp[2] >> 16) & 0xff) as usize]
        ^ t[3][((inp[2] >> 24) & 0xff) as usize]
        ^ t[4][((inp[1] >> 32) & 0xff) as usize]
        ^ t[5][((inp[1] >> 40) & 0xff) as usize]
        ^ t[6][((inp[0] >> 48) & 0xff) as usize]
        ^ t[7][((inp[0] >> 56) & 0xff) as usize];
}

fn kalina_g512(t: &[[u64; 256]; 8], inp: &[u64], out: &mut [u64]) {
    let inp8: [u64; 8] = [
        inp[0], inp[1], inp[2], inp[3], inp[4], inp[5], inp[6], inp[7],
    ];
    let mut tmp = [0u64; 8];
    bt_xor512(t, &inp8, &mut tmp, &[0u64; 8]);
    out.copy_from_slice(&tmp);
}

fn subrowcol128(ctx: &KalynaCore, state: &mut [u64]) {
    let mut point = [0u64; 2];
    kalina_g128(&ctx.p_boxrowcol, state, &mut point);
    state[..2].copy_from_slice(&point);
}

fn subrowcol256(ctx: &KalynaCore, state: &mut [u64]) {
    let mut point = [0u64; 4];
    kalina_g256(&ctx.p_boxrowcol, state, &mut point);
    state[..4].copy_from_slice(&point);
}

fn subrowcol512(ctx: &KalynaCore, state: &mut [u64]) {
    let mut point = [0u64; 8];
    kalina_g512(&ctx.p_boxrowcol, state, &mut point);
    state[..8].copy_from_slice(&point);
}

fn basic_transform_128(ctx: &KalynaCore, state: &mut [u64]) {
    let t = p_box(&ctx.p_boxrowcol);
    let rkey = &ctx.p_rkeys;
    let mut st = [state[0], state[1]];
    let mut point = [0u64; 2];
    st[0] = st[0].wrapping_add(rkey[0]);
    st[1] = st[1].wrapping_add(rkey[1]);
    bt_xor128(t, &st, &mut point, &rkey[2..]);
    bt_xor128(t, &point, &mut st, &rkey[4..]);
    bt_xor128(t, &st, &mut point, &rkey[6..]);
    bt_xor128(t, &point, &mut st, &rkey[8..]);
    bt_xor128(t, &st, &mut point, &rkey[10..]);
    bt_xor128(t, &point, &mut st, &rkey[12..]);
    bt_xor128(t, &st, &mut point, &rkey[14..]);
    bt_xor128(t, &point, &mut st, &rkey[16..]);
    bt_xor128(t, &st, &mut point, &rkey[18..]);
    bt_add128(t, &point, &mut st, &rkey[20..]);
    state[..2].copy_from_slice(&st);
}

fn basic_transform_128_256(ctx: &KalynaCore, state: &mut [u64]) {
    let t = p_box(&ctx.p_boxrowcol);
    let rkey = &ctx.p_rkeys;
    let mut st = [state[0], state[1]];
    let mut point = [0u64; 2];
    st[0] = st[0].wrapping_add(rkey[0]);
    st[1] = st[1].wrapping_add(rkey[1]);
    let mut k = 2usize;
    while k + 4 < 28 {
        bt_xor128(t, &st, &mut point, &rkey[k..]);
        bt_xor128(t, &point, &mut st, &rkey[(k + 2)..]);
        k += 4;
    }
    bt_xor128(t, &st, &mut point, &rkey[26..]);
    bt_add128(t, &point, &mut st, &rkey[28..]);
    state[..2].copy_from_slice(&st);
}

fn basic_transform_256(ctx: &KalynaCore, state: &mut [u64]) {
    let t = p_box(&ctx.p_boxrowcol);
    let rkey = &ctx.p_rkeys;
    let mut st = [state[0], state[1], state[2], state[3]];
    let mut point = [0u64; 4];
    for i in 0..4 {
        st[i] = st[i].wrapping_add(rkey[i]);
    }
    let mut k = 4usize;
    while k + 8 < 56 {
        bt_xor256(t, &st, &mut point, &rkey[k..]);
        bt_xor256(t, &point, &mut st, &rkey[(k + 4)..]);
        k += 8;
    }
    bt_xor256(t, &st, &mut point, &rkey[52..]);
    bt_add256(t, &point, &mut st, &rkey[56..]);
    state[..4].copy_from_slice(&st);
}

fn basic_transform_256_512(ctx: &KalynaCore, state: &mut [u64]) {
    let t = p_box(&ctx.p_boxrowcol);
    let rkey = &ctx.p_rkeys;
    let mut st = [state[0], state[1], state[2], state[3]];
    let mut point = [0u64; 4];
    for i in 0..4 {
        st[i] = st[i].wrapping_add(rkey[i]);
    }
    let mut k = 4usize;
    while k + 8 < 72 {
        bt_xor256(t, &st, &mut point, &rkey[k..]);
        bt_xor256(t, &point, &mut st, &rkey[(k + 4)..]);
        k += 8;
    }
    bt_xor256(t, &st, &mut point, &rkey[68..]);
    bt_add256(t, &point, &mut st, &rkey[72..]);
    state[..4].copy_from_slice(&st);
}

fn basic_transform_512(ctx: &KalynaCore, state: &mut [u64]) {
    let t = p_box(&ctx.p_boxrowcol);
    let rkey = &ctx.p_rkeys;
    let mut st = [
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    ];
    let mut point = [0u64; 8];
    for i in 0..8 {
        st[i] = st[i].wrapping_add(rkey[i]);
    }
    let mut k = 8usize;
    while k + 16 < 144 {
        bt_xor512(t, &st, &mut point, &rkey[k..]);
        bt_xor512(t, &point, &mut st, &rkey[(k + 8)..]);
        k += 16;
    }
    bt_xor512(t, &st, &mut point, &rkey[136..]);
    bt_add512(t, &point, &mut st, &rkey[144..]);
    state[..8].copy_from_slice(&st);
}

fn inv_subrowcol_xor128(state: &[u64; 2], out: &mut [u64; 2], rkey: &[u64], t: &[[u64; 256]; 8]) {
    let (s0, s1) = (state[0], state[1]);
    out[0] = rkey[0]
        ^ t[0][(s0 & 0xff) as usize]
        ^ t[1][((s0 >> 8) & 0xff) as usize]
        ^ t[2][((s0 >> 16) & 0xff) as usize]
        ^ t[3][((s0 >> 24) & 0xff) as usize]
        ^ t[4][((s1 >> 32) & 0xff) as usize]
        ^ t[5][((s1 >> 40) & 0xff) as usize]
        ^ t[6][((s1 >> 48) & 0xff) as usize]
        ^ t[7][((s1 >> 56) & 0xff) as usize];
    out[1] = rkey[1]
        ^ t[0][(s1 & 0xff) as usize]
        ^ t[1][((s1 >> 8) & 0xff) as usize]
        ^ t[2][((s1 >> 16) & 0xff) as usize]
        ^ t[3][((s1 >> 24) & 0xff) as usize]
        ^ t[4][((s0 >> 32) & 0xff) as usize]
        ^ t[5][((s0 >> 40) & 0xff) as usize]
        ^ t[6][((s0 >> 48) & 0xff) as usize]
        ^ t[7][((s0 >> 56) & 0xff) as usize];
}

fn inv_subrowcol_xor256(state: &[u64; 4], out: &mut [u64; 4], rkey: &[u64], t: &[[u64; 256]; 8]) {
    let (s0, s1, s2, s3) = (state[0], state[1], state[2], state[3]);
    out[0] = rkey[0]
        ^ t[0][(s0 & 0xff) as usize]
        ^ t[1][((s0 >> 8) & 0xff) as usize]
        ^ t[2][((s1 >> 16) & 0xff) as usize]
        ^ t[3][((s1 >> 24) & 0xff) as usize]
        ^ t[4][((s2 >> 32) & 0xff) as usize]
        ^ t[5][((s2 >> 40) & 0xff) as usize]
        ^ t[6][((s3 >> 48) & 0xff) as usize]
        ^ t[7][((s3 >> 56) & 0xff) as usize];
    out[1] = rkey[1]
        ^ t[0][(s1 & 0xff) as usize]
        ^ t[1][((s1 >> 8) & 0xff) as usize]
        ^ t[2][((s2 >> 16) & 0xff) as usize]
        ^ t[3][((s2 >> 24) & 0xff) as usize]
        ^ t[4][((s3 >> 32) & 0xff) as usize]
        ^ t[5][((s3 >> 40) & 0xff) as usize]
        ^ t[6][((s0 >> 48) & 0xff) as usize]
        ^ t[7][((s0 >> 56) & 0xff) as usize];
    out[2] = rkey[2]
        ^ t[0][(s2 & 0xff) as usize]
        ^ t[1][((s2 >> 8) & 0xff) as usize]
        ^ t[2][((s3 >> 16) & 0xff) as usize]
        ^ t[3][((s3 >> 24) & 0xff) as usize]
        ^ t[4][((s0 >> 32) & 0xff) as usize]
        ^ t[5][((s0 >> 40) & 0xff) as usize]
        ^ t[6][((s1 >> 48) & 0xff) as usize]
        ^ t[7][((s1 >> 56) & 0xff) as usize];
    out[3] = rkey[3]
        ^ t[0][(s3 & 0xff) as usize]
        ^ t[1][((s3 >> 8) & 0xff) as usize]
        ^ t[2][((s0 >> 16) & 0xff) as usize]
        ^ t[3][((s0 >> 24) & 0xff) as usize]
        ^ t[4][((s1 >> 32) & 0xff) as usize]
        ^ t[5][((s1 >> 40) & 0xff) as usize]
        ^ t[6][((s2 >> 48) & 0xff) as usize]
        ^ t[7][((s2 >> 56) & 0xff) as usize];
}

fn inv_subrowcol_xor512(state: &[u64; 8], out: &mut [u64; 8], rkey: &[u64], t: &[[u64; 256]; 8]) {
    let s = state;
    out[0] = rkey[0]
        ^ t[0][(s[0] & 0xff) as usize]
        ^ t[1][((s[1] >> 8) & 0xff) as usize]
        ^ t[2][((s[2] >> 16) & 0xff) as usize]
        ^ t[3][((s[3] >> 24) & 0xff) as usize]
        ^ t[4][((s[4] >> 32) & 0xff) as usize]
        ^ t[5][((s[5] >> 40) & 0xff) as usize]
        ^ t[6][((s[6] >> 48) & 0xff) as usize]
        ^ t[7][((s[7] >> 56) & 0xff) as usize];
    out[1] = rkey[1]
        ^ t[0][(s[1] & 0xff) as usize]
        ^ t[1][((s[2] >> 8) & 0xff) as usize]
        ^ t[2][((s[3] >> 16) & 0xff) as usize]
        ^ t[3][((s[4] >> 24) & 0xff) as usize]
        ^ t[4][((s[5] >> 32) & 0xff) as usize]
        ^ t[5][((s[6] >> 40) & 0xff) as usize]
        ^ t[6][((s[7] >> 48) & 0xff) as usize]
        ^ t[7][((s[0] >> 56) & 0xff) as usize];
    out[2] = rkey[2]
        ^ t[0][(s[2] & 0xff) as usize]
        ^ t[1][((s[3] >> 8) & 0xff) as usize]
        ^ t[2][((s[4] >> 16) & 0xff) as usize]
        ^ t[3][((s[5] >> 24) & 0xff) as usize]
        ^ t[4][((s[6] >> 32) & 0xff) as usize]
        ^ t[5][((s[7] >> 40) & 0xff) as usize]
        ^ t[6][((s[0] >> 48) & 0xff) as usize]
        ^ t[7][((s[1] >> 56) & 0xff) as usize];
    out[3] = rkey[3]
        ^ t[0][(s[3] & 0xff) as usize]
        ^ t[1][((s[4] >> 8) & 0xff) as usize]
        ^ t[2][((s[5] >> 16) & 0xff) as usize]
        ^ t[3][((s[6] >> 24) & 0xff) as usize]
        ^ t[4][((s[7] >> 32) & 0xff) as usize]
        ^ t[5][((s[0] >> 40) & 0xff) as usize]
        ^ t[6][((s[1] >> 48) & 0xff) as usize]
        ^ t[7][((s[2] >> 56) & 0xff) as usize];
    out[4] = rkey[4]
        ^ t[0][(s[4] & 0xff) as usize]
        ^ t[1][((s[5] >> 8) & 0xff) as usize]
        ^ t[2][((s[6] >> 16) & 0xff) as usize]
        ^ t[3][((s[7] >> 24) & 0xff) as usize]
        ^ t[4][((s[0] >> 32) & 0xff) as usize]
        ^ t[5][((s[1] >> 40) & 0xff) as usize]
        ^ t[6][((s[2] >> 48) & 0xff) as usize]
        ^ t[7][((s[3] >> 56) & 0xff) as usize];
    out[5] = rkey[5]
        ^ t[0][(s[5] & 0xff) as usize]
        ^ t[1][((s[6] >> 8) & 0xff) as usize]
        ^ t[2][((s[7] >> 16) & 0xff) as usize]
        ^ t[3][((s[0] >> 24) & 0xff) as usize]
        ^ t[4][((s[1] >> 32) & 0xff) as usize]
        ^ t[5][((s[2] >> 40) & 0xff) as usize]
        ^ t[6][((s[3] >> 48) & 0xff) as usize]
        ^ t[7][((s[4] >> 56) & 0xff) as usize];
    out[6] = rkey[6]
        ^ t[0][(s[6] & 0xff) as usize]
        ^ t[1][((s[7] >> 8) & 0xff) as usize]
        ^ t[2][((s[0] >> 16) & 0xff) as usize]
        ^ t[3][((s[1] >> 24) & 0xff) as usize]
        ^ t[4][((s[2] >> 32) & 0xff) as usize]
        ^ t[5][((s[3] >> 40) & 0xff) as usize]
        ^ t[6][((s[4] >> 48) & 0xff) as usize]
        ^ t[7][((s[5] >> 56) & 0xff) as usize];
    out[7] = rkey[7]
        ^ t[0][(s[7] & 0xff) as usize]
        ^ t[1][((s[0] >> 8) & 0xff) as usize]
        ^ t[2][((s[1] >> 16) & 0xff) as usize]
        ^ t[3][((s[2] >> 24) & 0xff) as usize]
        ^ t[4][((s[3] >> 32) & 0xff) as usize]
        ^ t[5][((s[4] >> 40) & 0xff) as usize]
        ^ t[6][((s[5] >> 48) & 0xff) as usize]
        ^ t[7][((s[6] >> 56) & 0xff) as usize];
}

fn apply_sbox_rev_word(sbox_rev: &[u8], s0: u64, s1: u64, rkey: u64) -> u64 {
    (u64::from(sbox_rev[(s0 & 0xff) as usize])
        ^ (u64::from(sbox_rev[256 + ((s0 >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sbox_rev[2 * 256 + ((s0 >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sbox_rev[3 * 256 + ((s0 >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sbox_rev[((s1 >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sbox_rev[256 + ((s1 >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sbox_rev[2 * 256 + ((s1 >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sbox_rev[3 * 256 + ((s1 >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rkey)
}

fn inv_subrowcol_sub128(ctx: &KalynaCore, state: &[u64; 2], out: &mut [u64; 2], rkey: &[u64]) {
    out[0] = apply_sbox_rev_word(&ctx.sbox_rev, state[0], state[1], rkey[0]);
    out[1] = apply_sbox_rev_word(&ctx.sbox_rev, state[1], state[0], rkey[1]);
}

fn inv_subrowcol_sub256(ctx: &KalynaCore, state: &[u64; 4], out: &mut [u64; 4], rkey: &[u64]) {
    let (s0, s1, s2, s3) = (state[0], state[1], state[2], state[3]);
    let sb = &ctx.sbox_rev;
    out[0] = (u64::from(sb[(s0 & 0xff) as usize])
        ^ (u64::from(sb[256 + ((s0 >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sb[2 * 256 + ((s1 >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sb[3 * 256 + ((s1 >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sb[((s2 >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sb[256 + ((s2 >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sb[2 * 256 + ((s3 >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sb[3 * 256 + ((s3 >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rkey[0]);
    out[1] = (u64::from(sb[(s1 & 0xff) as usize])
        ^ (u64::from(sb[256 + ((s1 >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sb[2 * 256 + ((s2 >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sb[3 * 256 + ((s2 >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sb[((s3 >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sb[256 + ((s3 >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sb[2 * 256 + ((s0 >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sb[3 * 256 + ((s0 >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rkey[1]);
    out[2] = (u64::from(sb[(s2 & 0xff) as usize])
        ^ (u64::from(sb[256 + ((s2 >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sb[2 * 256 + ((s3 >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sb[3 * 256 + ((s3 >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sb[((s0 >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sb[256 + ((s0 >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sb[2 * 256 + ((s1 >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sb[3 * 256 + ((s1 >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rkey[2]);
    out[3] = (u64::from(sb[(s3 & 0xff) as usize])
        ^ (u64::from(sb[256 + ((s3 >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sb[2 * 256 + ((s0 >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sb[3 * 256 + ((s0 >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sb[((s1 >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sb[256 + ((s1 >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sb[2 * 256 + ((s2 >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sb[3 * 256 + ((s2 >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rkey[3]);
}

fn inv_subrowcol_sub_word512(sb: &[u8], s: &[u64; 8], i: usize, rk: u64) -> u64 {
    let a = s[i];
    let b = s[(i + 1) % 8];
    let c = s[(i + 2) % 8];
    let d = s[(i + 3) % 8];
    let e = s[(i + 4) % 8];
    let f = s[(i + 5) % 8];
    let g = s[(i + 6) % 8];
    let h = s[(i + 7) % 8];
    (u64::from(sb[(a & 0xff) as usize])
        ^ (u64::from(sb[256 + ((b >> 8) & 0xff) as usize]) << 8)
        ^ (u64::from(sb[2 * 256 + ((c >> 16) & 0xff) as usize]) << 16)
        ^ (u64::from(sb[3 * 256 + ((d >> 24) & 0xff) as usize]) << 24)
        ^ (u64::from(sb[((e >> 32) & 0xff) as usize]) << 32)
        ^ (u64::from(sb[256 + ((f >> 40) & 0xff) as usize]) << 40)
        ^ (u64::from(sb[2 * 256 + ((g >> 48) & 0xff) as usize]) << 48)
        ^ (u64::from(sb[3 * 256 + ((h >> 56) & 0xff) as usize]) << 56))
        .wrapping_sub(rk)
}

fn inv_subrowcol_sub512(ctx: &KalynaCore, state: &[u64; 8], out: &mut [u64; 8], rkey: &[u64]) {
    let sb = &ctx.sbox_rev;
    for i in 0..8 {
        out[i] = inv_subrowcol_sub_word512(sb, state, i, rkey[i]);
    }
}

fn invert_state_word128(ctx: &KalynaCore, state: &mut [u64; 2]) {
    let t = &ctx.p_boxrowcol_rev;
    let sb = &ctx.sbox;
    for word in state.iter_mut() {
        *word = t[0][sb[(*word & 0xff) as usize] as usize]
            ^ t[1][sb[256 + ((*word >> 8) & 0xff) as usize] as usize]
            ^ t[2][sb[2 * 256 + ((*word >> 16) & 0xff) as usize] as usize]
            ^ t[3][sb[3 * 256 + ((*word >> 24) & 0xff) as usize] as usize]
            ^ t[4][sb[((*word >> 32) & 0xff) as usize] as usize]
            ^ t[5][sb[256 + ((*word >> 40) & 0xff) as usize] as usize]
            ^ t[6][sb[2 * 256 + ((*word >> 48) & 0xff) as usize] as usize]
            ^ t[7][sb[3 * 256 + ((*word >> 56) & 0xff) as usize] as usize];
    }
}

fn invert_state(ctx: &KalynaCore, state: &mut [u64]) {
    match ctx.block_len {
        BLOCK_128 => invert_state_word128(ctx, state.try_into().unwrap()),
        BLOCK_256 => {
            let s: &mut [u64; 4] = state.try_into().unwrap();
            for w in s.iter_mut() {
                let mut one = [*w, 0];
                invert_state_word128(ctx, &mut one);
                *w = one[0];
            }
        }
        BLOCK_512 => {
            let s: &mut [u64; 8] = state.try_into().unwrap();
            for w in s.iter_mut() {
                let mut one = [*w, 0];
                invert_state_word128(ctx, &mut one);
                *w = one[0];
            }
        }
        _ => {}
    }
}

fn decrypt_first_mix128(ctx: &KalynaCore, state: &mut [u64; 2]) {
    let t = &ctx.p_boxrowcol_rev;
    state[0] = t[0][S_BLOCKS[(state[0] & 0xff) as usize] as usize]
        ^ t[1][S_BLOCKS[256 + ((state[0] >> 8) & 0xff) as usize] as usize]
        ^ t[2][S_BLOCKS[2 * 256 + ((state[0] >> 16) & 0xff) as usize] as usize]
        ^ t[3][S_BLOCKS[3 * 256 + ((state[0] >> 24) & 0xff) as usize] as usize]
        ^ t[4][S_BLOCKS[((state[0] >> 32) & 0xff) as usize] as usize]
        ^ t[5][S_BLOCKS[256 + ((state[0] >> 40) & 0xff) as usize] as usize]
        ^ t[6][S_BLOCKS[2 * 256 + ((state[0] >> 48) & 0xff) as usize] as usize]
        ^ t[7][S_BLOCKS[3 * 256 + ((state[0] >> 56) & 0xff) as usize] as usize];
    state[1] = t[0][S_BLOCKS[(state[1] & 0xff) as usize] as usize]
        ^ t[1][S_BLOCKS[256 + ((state[1] >> 8) & 0xff) as usize] as usize]
        ^ t[2][S_BLOCKS[2 * 256 + ((state[1] >> 16) & 0xff) as usize] as usize]
        ^ t[3][S_BLOCKS[3 * 256 + ((state[1] >> 24) & 0xff) as usize] as usize]
        ^ t[4][S_BLOCKS[((state[1] >> 32) & 0xff) as usize] as usize]
        ^ t[5][S_BLOCKS[256 + ((state[1] >> 40) & 0xff) as usize] as usize]
        ^ t[6][S_BLOCKS[2 * 256 + ((state[1] >> 48) & 0xff) as usize] as usize]
        ^ t[7][S_BLOCKS[3 * 256 + ((state[1] >> 56) & 0xff) as usize] as usize];
}

fn subrowcol128_dec(ctx: &KalynaCore, state: &mut [u64]) {
    let rkey = &ctx.p_rkeys_rev;
    let t = &ctx.p_boxrowcol_rev;
    let mut st: [u64; 2] = state[..2].try_into().unwrap();
    let mut point = [0u64; 2];

    st[0] = st[0].wrapping_sub(rkey[20]);
    st[1] = st[1].wrapping_sub(rkey[21]);
    decrypt_first_mix128(ctx, &mut st);
    inv_subrowcol_xor128(&st, &mut point, &rkey[18..], t);
    inv_subrowcol_xor128(&point, &mut st, &rkey[16..], t);
    inv_subrowcol_xor128(&st, &mut point, &rkey[14..], t);
    inv_subrowcol_xor128(&point, &mut st, &rkey[12..], t);
    inv_subrowcol_xor128(&st, &mut point, &rkey[10..], t);
    inv_subrowcol_xor128(&point, &mut st, &rkey[8..], t);
    inv_subrowcol_xor128(&st, &mut point, &rkey[6..], t);
    inv_subrowcol_xor128(&point, &mut st, &rkey[4..], t);
    inv_subrowcol_xor128(&st, &mut point, &rkey[2..], t);
    inv_subrowcol_sub128(ctx, &point, &mut st, &rkey[..2]);
    state[..2].copy_from_slice(&st);
}

macro_rules! dec_rounds128 {
    ($ctx:expr, $state:expr, $final_sub:expr, $start:expr) => {{
        let rkey = &$ctx.p_rkeys_rev;
        let t = &$ctx.p_boxrowcol_rev;
        let mut st: [u64; 2] = $state[..2].try_into().unwrap();
        let mut point = [0u64; 2];
        st[0] = st[0].wrapping_sub(rkey[$final_sub]);
        st[1] = st[1].wrapping_sub(rkey[$final_sub + 1]);
        invert_state($ctx, &mut st);
        let mut k = $start;
        while k > 4 {
            inv_subrowcol_xor128(&st, &mut point, &rkey[k..], t);
            inv_subrowcol_xor128(&point, &mut st, &rkey[(k - 2)..], t);
            k -= 4;
        }
        inv_subrowcol_xor128(&st, &mut point, &rkey[2..], t);
        inv_subrowcol_sub128($ctx, &point, &mut st, &rkey[..2]);
        $state[..2].copy_from_slice(&st);
    }};
}

fn subrowcol128_256_dec(ctx: &KalynaCore, state: &mut [u64]) {
    dec_rounds128!(ctx, state, 28, 26);
}

fn subrowcol256_dec(ctx: &KalynaCore, state: &mut [u64]) {
    let rkey = &ctx.p_rkeys_rev;
    let t = &ctx.p_boxrowcol_rev;
    let mut st: [u64; 4] = state[..4].try_into().unwrap();
    let mut point = [0u64; 4];
    for i in 0..4 {
        st[i] = st[i].wrapping_sub(rkey[56 + i]);
    }
    invert_state(ctx, &mut st);
    let mut k = 52usize;
    while k > 4 {
        inv_subrowcol_xor256(&st, &mut point, &rkey[k..], t);
        inv_subrowcol_xor256(&point, &mut st, &rkey[(k - 4)..], t);
        k -= 8;
    }
    inv_subrowcol_xor256(&st, &mut point, &rkey[4..], t);
    inv_subrowcol_sub256(ctx, &point, &mut st, &rkey[..4]);
    state[..4].copy_from_slice(&st);
}

fn subrowcol256_512_dec(ctx: &KalynaCore, state: &mut [u64]) {
    let rkey = &ctx.p_rkeys_rev;
    let t = &ctx.p_boxrowcol_rev;
    let mut st: [u64; 4] = state[..4].try_into().unwrap();
    let mut point = [0u64; 4];
    for i in 0..4 {
        st[i] = st[i].wrapping_sub(rkey[72 + i]);
    }
    invert_state(ctx, &mut st);
    let mut k = 68usize;
    while k > 4 {
        inv_subrowcol_xor256(&st, &mut point, &rkey[k..], t);
        inv_subrowcol_xor256(&point, &mut st, &rkey[(k - 4)..], t);
        k -= 8;
    }
    inv_subrowcol_xor256(&st, &mut point, &rkey[4..], t);
    inv_subrowcol_sub256(ctx, &point, &mut st, &rkey[..4]);
    state[..4].copy_from_slice(&st);
}

fn subrowcol512_dec(ctx: &KalynaCore, state: &mut [u64]) {
    let rkey = &ctx.p_rkeys_rev;
    let t = &ctx.p_boxrowcol_rev;
    let mut st: [u64; 8] = state[..8].try_into().unwrap();
    let mut point = [0u64; 8];
    for i in 0..8 {
        st[i] = st[i].wrapping_sub(rkey[144 + i]);
    }
    invert_state(ctx, &mut st);
    let mut k = 136usize;
    while k > 8 {
        inv_subrowcol_xor512(&st, &mut point, &rkey[k..], t);
        inv_subrowcol_xor512(&point, &mut st, &rkey[(k - 8)..], t);
        k -= 16;
    }
    inv_subrowcol_xor512(&st, &mut point, &rkey[8..], t);
    inv_subrowcol_sub512(ctx, &point, &mut st, &rkey[..8]);
    state[..8].copy_from_slice(&st);
}

fn reverse_rkey(ctx: &mut KalynaCore) {
    let invert_indices: &[usize] = match (ctx.block_len, ctx.key_len) {
        (BLOCK_128, KEY_128) => &[18, 16, 14, 12, 10, 8, 6, 4, 2],
        (BLOCK_128, KEY_256) => &[26, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2],
        (BLOCK_256, KEY_256) => &[52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4],
        (BLOCK_256, KEY_512) => &[
            68, 64, 60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4,
        ],
        (BLOCK_512, KEY_512) => &[
            136, 128, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8,
        ],
        _ => &[],
    };
    let w = ctx.block_len / 8;
    for &idx in invert_indices {
        let mut tmp = [0u64; 8];
        tmp[..w].copy_from_slice(&ctx.p_rkeys_rev[idx..idx + w]);
        invert_state(ctx, &mut tmp[..w]);
        ctx.p_rkeys_rev[idx..idx + w].copy_from_slice(&tmp[..w]);
    }
}

fn sub_shift_mix_xor(ctx: &KalynaCore, key: &[u64], state: &mut [u64]) {
    ctx.subrowcol(state);
    kalina_xor_inplace(state, key);
}

fn sub_shift_mix_add(ctx: &KalynaCore, key: &[u64], state: &mut [u64]) {
    ctx.subrowcol(state);
    kalina_add(key, state);
}

fn p_help_round_key(key: &[u8], ctx: &KalynaCore, hrkey: &mut [u64]) -> Result<()> {
    let wblock = ctx.block_len / 8;
    let mut key64 = vec![0u64; key.len().div_ceil(8)];
    bytes_to_u64(key, &mut key64);

    if ctx.block_len == ctx.key_len {
        kalina_add(&key64[..wblock], &mut hrkey[..wblock]);
        let kcopy = key64[..wblock].to_vec();
        let mut hr = hrkey[..wblock].to_vec();
        sub_shift_mix_xor(ctx, &kcopy, &mut hr);
        hrkey[..wblock].copy_from_slice(&hr);
        sub_shift_mix_add(ctx, &key64[..wblock], hrkey);
        ctx.subrowcol(hrkey);
    } else {
        kalina_add(&key64[..wblock], &mut hrkey[..wblock]);
        let ktail = key64[wblock..wblock + wblock].to_vec();
        let mut hr = hrkey[..wblock].to_vec();
        sub_shift_mix_xor(ctx, &ktail, &mut hr);
        hrkey[..wblock].copy_from_slice(&hr);
        sub_shift_mix_add(ctx, &key64[..wblock], hrkey);
        ctx.subrowcol(hrkey);
    }
    Ok(())
}

fn p_key_shift(key: &[u8], block_len: usize, key_len: usize, rounds: usize) -> Result<Vec<u64>> {
    let shift_key_size = key_len * ((rounds >> 1) + 1);
    let mut key_shift = vec![0u8; shift_key_size];

    if block_len == key_len {
        for i in 0..=(rounds >> 1) {
            let shift = 56 * i;
            for j in 0..key_len {
                key_shift[i * key_len + (j + shift) % key_len] = key[j];
            }
        }
    } else {
        for i in 0..=(rounds >> 1) {
            for j in 0..key_len {
                let shift = if i % 2 == 0 {
                    60 * i
                } else if key_len == KEY_256 {
                    48 - ((i >> 1) << 3)
                } else {
                    96 - ((i >> 1) << 3)
                };
                key_shift[i * key_len + (j + shift) % key_len] = key[j];
            }
        }
    }

    let mut out = vec![0u64; shift_key_size.div_ceil(8)];
    bytes_to_u64(&key_shift, &mut out);
    Ok(out)
}

fn precomputed_rkeys(
    ctx: &mut KalynaCore,
    precompute_keyshifts: &[u64],
    p_hrkey: &mut [u64],
) -> Result<()> {
    let block_len = ctx.block_len;
    let key_len = ctx.key_len / 8;
    let wblock_len = block_len / 8;
    let mut id8 = [0u8; 64];
    let mut id64 = [0u64; 8];
    let mut rkey = [0u64; 8];

    for i in 0..=(ctx.rounds >> 1) {
        let mut j = 0usize;
        while j < block_len {
            let shift = (1usize << i) >> 8;
            if shift > 0 {
                j += 1;
                if j < block_len {
                    id8[j] = 1u8.wrapping_shl((shift - 1) as u32);
                }
            } else {
                id8[j] = 1u8.wrapping_shl(i as u32);
                j += 1;
            }
            j += 1;
        }

        bytes_to_u64(&id8[..block_len], &mut id64[..wblock_len]);

        let base = i * (wblock_len * 2);
        ctx.p_rkeys[base..base + block_len / 8].copy_from_slice(&p_hrkey[..wblock_len]);
        kalina_add(
            &id64[..wblock_len],
            &mut ctx.p_rkeys[base..base + wblock_len],
        );
        rkey[..wblock_len].copy_from_slice(&ctx.p_rkeys[base..base + wblock_len]);
        let ks_off = i * key_len;
        kalina_add(
            &precompute_keyshifts[ks_off..ks_off + wblock_len],
            &mut ctx.p_rkeys[base..base + wblock_len],
        );
        let rk = rkey[..wblock_len].to_vec();
        let mut slot = ctx.p_rkeys[base..base + wblock_len].to_vec();
        sub_shift_mix_xor(ctx, &rk, &mut slot);
        sub_shift_mix_add(ctx, &rk, &mut slot);
        ctx.p_rkeys[base..base + wblock_len].copy_from_slice(&slot);
        id8 = [0u8; 64];
    }

    let shift = block_len - (block_len / 4 + 3);
    let mut swap = [0u8; 64];
    let mut tmp = [0u8; 64];
    let mut i = 0usize;
    while i < ctx.rounds {
        u64_to_bytes(
            &ctx.p_rkeys[(i * wblock_len)..(i * wblock_len + wblock_len)],
            &mut swap[..block_len],
        );
        for j in 0..block_len {
            tmp[(j + shift) % block_len] = swap[j];
        }
        bytes_to_u64(
            &tmp[..block_len],
            &mut ctx.p_rkeys[((i + 1) * wblock_len)..],
        );
        i += 2;
    }
    Ok(())
}

/// Forward cipher (Cryptonite `crypt_basic_transform`).
pub fn crypt_basic_transform(core: &KalynaCore, input: &[u8], output: &mut [u8]) -> Result<()> {
    core.encrypt_block(input, output)
}

/// In-place forward cipher when input and output are the same buffer.
pub fn crypt_basic_transform_in_place(core: &KalynaCore, block: &mut [u8]) -> Result<()> {
    let bl = core.block_len;
    let mut tmp = vec![0u8; bl];
    crypt_basic_transform(core, block, &mut tmp)?;
    block.copy_from_slice(&tmp);
    Ok(())
}

/// Memory-safe XOR (Cryptonite `kalina_xor`).
pub fn kalina_xor_bytes(arg1: &[u8], arg2: &[u8], len: usize, out: &mut [u8]) {
    debug_assert!(arg1.len() >= len && arg2.len() >= len && out.len() >= len);
    match len {
        16 => {
            let a = u64::from_le_bytes(arg1[..8].try_into().unwrap())
                ^ u64::from_le_bytes(arg2[..8].try_into().unwrap());
            let b = u64::from_le_bytes(arg1[8..16].try_into().unwrap())
                ^ u64::from_le_bytes(arg2[8..16].try_into().unwrap());
            out[..8].copy_from_slice(&a.to_le_bytes());
            out[8..16].copy_from_slice(&b.to_le_bytes());
        }
        32 => {
            for i in 0..4 {
                let off = i * 8;
                let v = u64::from_le_bytes(arg1[off..off + 8].try_into().unwrap())
                    ^ u64::from_le_bytes(arg2[off..off + 8].try_into().unwrap());
                out[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        64 => {
            for i in 0..8 {
                let off = i * 8;
                let v = u64::from_le_bytes(arg1[off..off + 8].try_into().unwrap())
                    ^ u64::from_le_bytes(arg2[off..off + 8].try_into().unwrap());
                out[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        _ => {
            for i in 0..len {
                out[i] = arg1[i] ^ arg2[i];
            }
        }
    }
}

/// CTR counter increment (Cryptonite `gamma_gen`).
pub fn gamma_gen(feed: &mut [u8]) {
    let mut i = 0usize;
    loop {
        feed[i] = feed[i].wrapping_add(1);
        if feed[i] != 0 {
            break;
        }
        i += 1;
        if i >= feed.len() {
            break;
        }
    }
}
