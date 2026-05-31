//! DSTU 7564 KMAC — Cryptonite-compatible streaming (`dstu7564_init_kmac` / `update_kmac` / `final_kmac`).
//!
//! Algorithm: `H(PAD(K) || PAD(M) || (~K))` with `mac_len` ∈ {32, 48, 64}.

use super::kupyna_engine::{
    compress_long, compress_short, t_xor_l_long, t_xor_l_short,
    utils::{write_u64_be, xor},
    COLS_LONG, COLS_SHORT,
};
use crate::{Error, Result};

const BLOCK_SHORT: usize = 64;
const BLOCK_LONG: usize = 128;
const LAST_BLOCK_CAP: usize = BLOCK_LONG * 2;

struct HmacState {
    invert_key: [u8; BLOCK_LONG],
    key_len: usize,
}

enum Engine {
    Short { state: [u64; COLS_SHORT] },
    Long { state: [u64; COLS_LONG] },
}

impl Engine {
    fn block_size(&self) -> usize {
        match self {
            Engine::Short { .. } => BLOCK_SHORT,
            Engine::Long { .. } => BLOCK_LONG,
        }
    }

    fn digest_block(&mut self, block: &[u8]) {
        match self {
            Engine::Short { state } => {
                let block: &[u8; BLOCK_SHORT] = block.try_into().expect("short block");
                compress_short(state, block);
            }
            Engine::Long { state } => {
                let block: &[u8; BLOCK_LONG] = block.try_into().expect("long block");
                compress_long(state, block);
            }
        }
    }

    fn output_transformation(&mut self, hash_nbytes: usize) -> Vec<u8> {
        let block_size = self.block_size();
        let mut out = vec![0u8; hash_nbytes];
        match self {
            Engine::Short { state } => {
                let t = t_xor_l_short(*state);
                *state = xor(*state, t);
                let bytes = state_to_be_bytes_short(*state);
                out.copy_from_slice(&bytes[block_size - hash_nbytes..]);
                *state = init_state_short();
            }
            Engine::Long { state } => {
                let t = t_xor_l_long(*state);
                *state = xor(*state, t);
                let bytes = state_to_be_bytes_long(*state);
                out.copy_from_slice(&bytes[block_size - hash_nbytes..]);
                *state = init_state_long();
            }
        }
        out
    }
}

fn init_state_short() -> [u64; COLS_SHORT] {
    let mut state = [0u64; COLS_SHORT];
    state[0] = 0x40 << 56;
    state
}

fn init_state_long() -> [u64; COLS_LONG] {
    let mut state = [0u64; COLS_LONG];
    state[0] = 0x80 << 56;
    state
}

fn state_to_be_bytes_short(state: [u64; COLS_SHORT]) -> [u8; BLOCK_SHORT] {
    let mut out = [0u8; BLOCK_SHORT];
    write_u64_be(&state, &mut out);
    out
}

fn state_to_be_bytes_long(state: [u64; COLS_LONG]) -> [u8; BLOCK_LONG] {
    let mut out = [0u8; BLOCK_LONG];
    write_u64_be(&state, &mut out);
    out
}

/// Kupyna padding (Cryptonite `padding()` / `kupyna` `digest_pad` length field).
#[allow(clippy::explicit_counter_loop)]
fn padding(buf: &mut [u8], buf_len_out: usize, buf_len_out_bits: u64, nbytes: usize) -> usize {
    let cur_pos = buf_len_out % nbytes;
    let zero_nbytes =
        (((!buf_len_out_bits.wrapping_add(97)) % ((nbytes << 3) as u64)) >> 3) as usize;
    buf[cur_pos] = 0x80;
    let cur_pos = cur_pos + 1;
    let end_zeros = cur_pos + zero_nbytes;
    buf[cur_pos..end_zeros].fill(0);
    let mut cur_pos = end_zeros;
    for i in 0..(96 >> 3) {
        if i < size_of::<usize>() {
            buf[cur_pos] = ((buf_len_out_bits >> (i << 3)) & 0xFF) as u8;
        } else {
            buf[cur_pos] = 0;
        }
        cur_pos += 1;
    }
    zero_nbytes + 1 + (96 >> 3)
}

/// Streaming KMAC context (Cryptonite `Dstu7564Ctx` for KMAC).
pub struct Kmac {
    engine: Engine,
    last_block: [u8; LAST_BLOCK_CAP],
    last_block_el: usize,
    msg_tot_len: u64,
    hash_nbytes: usize,
    hmac: Option<HmacState>,
    is_inited: bool,
}

impl Kmac {
    /// `dstu7564_init_kmac`: absorb `PAD(K)` into the hash state.
    pub fn new(key: &[u8], mac_len: usize) -> Result<Self> {
        if mac_len != 32 && mac_len != 48 && mac_len != 64 {
            return Err(Error::InvalidParam(format!(
                "KMAC output length must be 32, 48, or 64, got {mac_len}"
            )));
        }

        let engine = if mac_len <= 32 {
            Engine::Short {
                state: init_state_short(),
            }
        } else {
            Engine::Long {
                state: init_state_long(),
            }
        };
        let block_size = engine.block_size();

        let mut ctx = Self {
            engine,
            last_block: [0u8; LAST_BLOCK_CAP],
            last_block_el: 0,
            msg_tot_len: 0,
            hash_nbytes: mac_len,
            hmac: None,
            is_inited: true,
        };

        let key_len = key.len();
        let mut invert_key = [0u8; BLOCK_LONG];
        let mut key_buf = [0u8; BLOCK_LONG];
        key_buf[..key_len].copy_from_slice(key);
        for i in 0..key_len {
            invert_key[i] = !key_buf[i];
        }

        ctx.hmac = Some(HmacState {
            invert_key,
            key_len,
        });

        let padd_len = padding(&mut key_buf, key_len, (key_len as u64) << 3, block_size);
        ctx.msg_tot_len += (block_size as u64) << 3;

        let mut i = 0;
        while i < padd_len {
            let block = &key_buf[i..i + block_size];
            ctx.engine.digest_block(block);
            i += block_size;
        }

        ctx.hash_nbytes = mac_len;
        Ok(ctx)
    }

    /// `dstu7564_update_kmac`
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if !self.is_inited {
            return Err(Error::InvalidParam("KMAC context not initialized".into()));
        }
        self.update_inner(data);
        Ok(())
    }

    fn update_inner(&mut self, data: &[u8]) {
        let block_size = self.engine.block_size();
        let mut data_buf = data;
        let mut data_buf_len = data.len();

        self.msg_tot_len += (data_buf_len as u64) << 3;

        if self.last_block_el + data_buf_len < block_size {
            self.last_block[self.last_block_el..self.last_block_el + data_buf_len]
                .copy_from_slice(data_buf);
            self.last_block_el += data_buf_len;
            return;
        }

        let fill = block_size - self.last_block_el;
        self.last_block[self.last_block_el..block_size].copy_from_slice(&data_buf[..fill]);
        self.engine.digest_block(&self.last_block[..block_size]);
        self.last_block[..block_size].fill(0);

        data_buf = &data_buf[fill..];
        data_buf_len -= fill;

        let mut i = 0;
        while i + block_size <= data_buf_len {
            self.engine.digest_block(&data_buf[i..i + block_size]);
            i += block_size;
        }

        self.last_block_el = data_buf_len - i;
        if self.last_block_el != 0 {
            self.last_block[..self.last_block_el].copy_from_slice(&data_buf[i..]);
        }
    }

    /// `dstu7564_final_kmac`
    pub fn finalize(mut self) -> Result<Vec<u8>> {
        if !self.is_inited {
            return Err(Error::InvalidParam("KMAC context not initialized".into()));
        }
        self.is_inited = false;

        let block_size = self.engine.block_size();
        let hmac = self.hmac.as_ref().expect("KMAC hmac state set in new()");

        let msg_len = (self.msg_tot_len >> 3) - block_size as u64;
        self.msg_tot_len -= (self.last_block_el as u64) << 3;

        let padd_len = padding(
            &mut self.last_block,
            msg_len as usize,
            msg_len << 3,
            block_size,
        );

        let mut i = 0;
        while i < padd_len {
            self.msg_tot_len += (block_size as u64) << 3;
            self.engine
                .digest_block(&self.last_block[i..i + block_size]);
            i += block_size;
        }

        self.last_block[..block_size].fill(0);
        self.last_block_el = 0;

        self.msg_tot_len += (hmac.key_len as u64) << 3;

        self.last_block[..hmac.key_len].copy_from_slice(&hmac.invert_key[..hmac.key_len]);

        let padd_len = padding(
            &mut self.last_block,
            (self.msg_tot_len >> 3) as usize,
            self.msg_tot_len,
            block_size,
        );

        self.msg_tot_len -= (hmac.key_len as u64) << 3;
        self.last_block_el = 0;

        self.msg_tot_len += (block_size as u64) << 3;

        let mut i = 0;
        while i < padd_len {
            self.engine
                .digest_block(&self.last_block[i..i + block_size]);
            i += block_size;
        }

        Ok(self.engine.output_transformation(self.hash_nbytes))
    }
}

/// One-shot KMAC.
pub fn kmac(key: &[u8], data: &[u8], mac_len: usize) -> Result<Vec<u8>> {
    let mut ctx = Kmac::new(key, mac_len)?;
    ctx.update(data)?;
    ctx.finalize()
}
