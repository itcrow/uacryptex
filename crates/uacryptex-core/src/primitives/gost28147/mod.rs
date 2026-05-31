//! GOST 28147-89 block cipher (Cryptonite port, S-box 1 only).

use crate::primitives::byte_utils::{uint32_to_uint8, uint8_swap, uint8_to_uint32};
use crate::primitives::dstu4145::RandomBytes;
use crate::{Error, Result};

const SBOX_LEN: usize = 128;
const KEY_LEN: usize = 32;
const MAC_LEN: usize = 4;
const IV_LEN: usize = 8;

/// Wrapped key size (`gost28147_wrap_key` output).
pub const WRAP_KEY_LEN: usize = 44;

/// IV for the final CFB stage of GOST 28147 key wrap (Cryptonite `IV_WRAP`).
pub const IV_WRAP: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

const CTR_C1: u32 = 0x0101_0101;
const CTR_C2: u32 = 0x0101_0104;

pub const GOST28147_SBOX_LEN: usize = SBOX_LEN;

/// Default S-box 1 table (`GOST28147_SBOX_ID_1`).
pub fn default_sbox() -> [u8; SBOX_LEN] {
    GOST28147_SBOX_1
}

static GOST28147_SBOX_1: [u8; SBOX_LEN] = [
    0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2, 0x8, 0x0, 0xc,
    0x4, 0x9, 0x6, 0x7, 0xb, 0x2, 0x3, 0x1, 0xf, 0x5, 0xe, 0xa, 0xd, 0xf, 0x6, 0x5, 0x8, 0xe, 0xb,
    0xa, 0x4, 0xc, 0x0, 0x3, 0x7, 0x2, 0x9, 0x1, 0xd, 0x3, 0x8, 0xd, 0x9, 0x6, 0xb, 0xf, 0x0, 0x2,
    0x5, 0xc, 0xa, 0x4, 0xe, 0x1, 0x7, 0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5,
    0xb, 0x4, 0x3, 0xa, 0x2, 0x8, 0x9, 0x7, 0x5, 0xf, 0x0, 0xb, 0xc, 0x1, 0xd, 0xe, 0xa, 0x3, 0x6,
    0x4, 0x3, 0x8, 0xb, 0x5, 0x6, 0x4, 0xe, 0xa, 0x2, 0xc, 0x1, 0x7, 0x9, 0xf, 0xd, 0x0, 0x1, 0x2,
    0x3, 0xe, 0x6, 0xd, 0xb, 0x8, 0xf, 0xa, 0xc, 0x5, 0x7, 0x9, 0x0, 0x4,
];

static ENCRYPT_KEY_ORDER: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
];

static MAC_KEY_ORDER: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7];

#[inline]
fn sbox_transform(sbox: &[u32; 1024], x: u32) -> u32 {
    sbox[(x & 0xff) as usize]
        | sbox[256 + (((x >> 8) & 0xff) as usize)]
        | sbox[512 + (((x >> 16) & 0xff) as usize)]
        | sbox[768 + (((x >> 24) & 0xff) as usize)]
}

fn expand_sbox(raw: &[u8; SBOX_LEN]) -> [u32; 1024] {
    let mut sbox = [0u32; 1024];
    for i in 0..256 {
        sbox[i] = (raw[16 + (i >> 4)] << 4 | raw[i & 0xf]) as u32;
        sbox[256 + i] = ((raw[48 + (i >> 4)] << 4 | raw[32 + (i & 0xf)]) as u32) << 8;
        sbox[512 + i] = ((raw[80 + (i >> 4)] << 4 | raw[64 + (i & 0xf)]) as u32) << 16;
        sbox[768 + i] = ((raw[112 + (i >> 4)] << 4 | raw[96 + (i & 0xf)]) as u32) << 24;
        sbox[i] = sbox[i].rotate_left(11);
        sbox[256 + i] = sbox[256 + i].rotate_left(11);
        sbox[512 + i] = sbox[512 + i].rotate_left(11);
        sbox[768 + i] = sbox[768 + i].rotate_left(11);
    }
    sbox
}

/// Expand 64-byte DKE (Cryptonite `get_sbox_from_aid`) to 128-byte S-box table.
pub fn expand_dke(dke: &[u8]) -> Result<[u8; SBOX_LEN]> {
    if dke.len() != 64 {
        return Err(Error::InvalidParam(format!(
            "DKE must be 64 bytes, got {}",
            dke.len()
        )));
    }
    let mut sbox = [0u8; SBOX_LEN];
    let mut count = 0usize;
    for i in 0..8 {
        for j in 0..16 {
            sbox[count] = (dke[(i << 3) + (j >> 1)] >> (((!j) & 1) << 2)) & 0x0f;
            count += 1;
        }
    }
    Ok(sbox)
}

/// Pack 128-byte S-box into 64-byte DKE (inverse of `expand_dke`).
pub fn compress_sbox(raw: &[u8; SBOX_LEN]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..8 {
        for j in 0..16 {
            out[(i << 3) + (j >> 1)] |= raw[16 * i + j] << (((!j) & 1) << 2);
        }
    }
    out
}

/// Reverse byte order in place (`ba_swap` / `uint8_swap`).
pub fn byte_swap(buf: &mut [u8]) {
    uint8_swap(buf);
}

/// `gost28147_generate_key`: 32 random key bytes.
pub fn generate_key(rng: &mut dyn RandomBytes) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    rng.fill(&mut key)?;
    Ok(key)
}

pub fn base_cycle24(data: &mut [u32; 6], key: &[u32; 8], key_order: &[u8; 32], sbox: &[u32; 1024]) {
    for i in 0..16 {
        let ko0 = key_order[2 * i] as usize;
        let ko1 = key_order[2 * i + 1] as usize;

        let x1 = data[0].wrapping_add(key[ko0]);
        let x2 = data[2].wrapping_add(key[ko0]);
        let x3 = data[4].wrapping_add(key[ko0]);
        data[1] ^= sbox_transform(sbox, x1);
        data[3] ^= sbox_transform(sbox, x2);
        data[5] ^= sbox_transform(sbox, x3);

        let x1 = data[1].wrapping_add(key[ko1]);
        let x2 = data[3].wrapping_add(key[ko1]);
        let x3 = data[5].wrapping_add(key[ko1]);
        data[0] ^= sbox_transform(sbox, x1);
        data[2] ^= sbox_transform(sbox, x2);
        data[4] ^= sbox_transform(sbox, x3);
    }

    data.swap(0, 1);
    data.swap(2, 3);
    data.swap(4, 5);
}

pub fn base_cycle32(sbox: &[u32; 1024], src: &mut [u32; 8], k: &[u32; 32]) {
    let (k1, rest) = k.split_at(8);
    let (k2, rest) = rest.split_at(8);
    let (k3, k4) = rest.split_at(8);

    let mut i = 0usize;
    while i < 24 {
        let idx = i & 7;
        let x = src[0].wrapping_add(k1[idx]);
        let y = src[2].wrapping_add(k2[idx]);
        let z = src[4].wrapping_add(k3[idx]);
        let r = src[6].wrapping_add(k4[idx]);
        i += 1;

        src[1] ^= sbox_transform(sbox, x);
        src[3] ^= sbox_transform(sbox, y);
        src[5] ^= sbox_transform(sbox, z);
        src[7] ^= sbox_transform(sbox, r);

        let idx = i & 7;
        let x = src[1].wrapping_add(k1[idx]);
        let y = src[3].wrapping_add(k2[idx]);
        let z = src[5].wrapping_add(k3[idx]);
        let r = src[7].wrapping_add(k4[idx]);
        i += 1;

        src[0] ^= sbox_transform(sbox, x);
        src[2] ^= sbox_transform(sbox, y);
        src[4] ^= sbox_transform(sbox, z);
        src[6] ^= sbox_transform(sbox, r);
    }

    let mut i = 7i32;
    while i >= 0 {
        let idx0 = i as usize;
        let x = src[0].wrapping_add(k1[idx0]);
        let y = src[2].wrapping_add(k2[idx0]);
        let z = src[4].wrapping_add(k3[idx0]);
        let r = src[6].wrapping_add(k4[idx0]);

        src[1] ^= sbox_transform(sbox, x);
        src[3] ^= sbox_transform(sbox, y);
        src[5] ^= sbox_transform(sbox, z);
        src[7] ^= sbox_transform(sbox, r);

        i -= 1;
        let idx1 = i as usize;
        let x = src[1].wrapping_add(k1[idx1]);
        let y = src[3].wrapping_add(k2[idx1]);
        let z = src[5].wrapping_add(k3[idx1]);
        let r = src[7].wrapping_add(k4[idx1]);

        src[0] ^= sbox_transform(sbox, x);
        src[2] ^= sbox_transform(sbox, y);
        src[4] ^= sbox_transform(sbox, z);
        src[6] ^= sbox_transform(sbox, r);

        i -= 1;
    }

    src.swap(0, 1);
    src.swap(2, 3);
    src.swap(4, 5);
    src.swap(6, 7);
}

/// 8-byte block transform (`base_cycle8`; `rounds` is 16 for MAC, 32 for CFB/CTR feed).
fn base_cycle8(
    data: &mut [u32; 2],
    key: &[u32; 8],
    key_order: &[u8],
    rounds: usize,
    sbox: &[u32; 1024],
) {
    for i in (0..rounds).step_by(4) {
        let mut s = data[0].wrapping_add(key[key_order[i] as usize]);
        data[1] ^= sbox_transform(sbox, s);
        s = data[1].wrapping_add(key[key_order[i + 1] as usize]);
        data[0] ^= sbox_transform(sbox, s);
        s = data[0].wrapping_add(key[key_order[i + 2] as usize]);
        data[1] ^= sbox_transform(sbox, s);
        s = data[1].wrapping_add(key[key_order[i + 3] as usize]);
        data[0] ^= sbox_transform(sbox, s);
    }
    if rounds == 32 {
        data.swap(0, 1);
    }
}

fn ctr_next_feed(feed: &mut [u32; 6]) {
    feed[1] = feed[5].wrapping_add(CTR_C2);
    feed[0] = feed[4].wrapping_add(CTR_C1);
    if feed[1] < CTR_C2 {
        feed[1] = feed[1].wrapping_add(1);
    }
    for i in 1..3 {
        feed[2 * i + 1] = feed[2 * i - 1].wrapping_add(CTR_C2);
        feed[2 * i] = feed[2 * i - 2].wrapping_add(CTR_C1);
        if feed[2 * i + 1] < CTR_C2 {
            feed[2 * i + 1] = feed[2 * i + 1].wrapping_add(1);
        }
    }
}

enum Gost28147Mode {
    Ecb,
    Ctr {
        gamma: [u8; 24],
        feed: [u32; 6],
        offset: usize,
    },
    Cfb {
        gamma: [u8; 8],
        feed: [u8; 8],
        offset: usize,
    },
    Mac {
        mac: [u8; 8],
        offset: usize,
    },
}

/// GOST 28147-89 context (S-box 1 default; user S-box via `from_raw_sbox`).
pub struct Gost28147 {
    sbox: [u32; 1024],
    key: [u32; 8],
    mode: Option<Gost28147Mode>,
}

impl Default for Gost28147 {
    fn default() -> Self {
        Self::new()
    }
}

impl Gost28147 {
    /// `gost28147_alloc(GOST28147_SBOX_ID_1)`.
    pub fn new() -> Self {
        Self::from_raw_sbox(&GOST28147_SBOX_1)
    }

    /// `gost28147_alloc_user_sbox`.
    pub fn from_raw_sbox(raw: &[u8; SBOX_LEN]) -> Self {
        Self {
            sbox: expand_sbox(raw),
            key: [0; 8],
            mode: None,
        }
    }

    pub(crate) fn sbox(&self) -> &[u32; 1024] {
        &self.sbox
    }

    /// `gost28147_init_ecb`.
    pub fn init_ecb(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidParam(format!(
                "gost28147 key must be {KEY_LEN} bytes"
            )));
        }
        uint8_to_uint32(key, &mut self.key);
        self.mode = Some(Gost28147Mode::Ecb);
        Ok(())
    }

    /// `gost28147_init_cfb`.
    pub fn init_cfb(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidParam(format!(
                "gost28147 key must be {KEY_LEN} bytes"
            )));
        }
        if iv.len() != 8 {
            return Err(Error::InvalidParam("gost28147 CFB IV must be 8 bytes".into()));
        }
        uint8_to_uint32(key, &mut self.key);
        let mut feed = [0u8; 8];
        feed.copy_from_slice(iv);
        self.mode = Some(Gost28147Mode::Cfb {
            gamma: [0u8; 8],
            feed,
            offset: 8,
        });
        Ok(())
    }

    /// `gost28147_init_ctr` (OFB OID maps to CTR in Cryptonite).
    pub fn init_ctr(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidParam(format!(
                "gost28147 key must be {KEY_LEN} bytes"
            )));
        }
        if iv.len() != IV_LEN {
            return Err(Error::InvalidParam("gost28147 CTR IV must be 8 bytes".into()));
        }
        uint8_to_uint32(key, &mut self.key);
        let mut feed = [0u32; 6];
        let mut tail = [0u32; 2];
        uint8_to_uint32(iv, &mut tail);
        base_cycle8(&mut tail, &self.key, &ENCRYPT_KEY_ORDER, 32, &self.sbox);
        feed[4] = tail[0];
        feed[5] = tail[1];
        self.mode = Some(Gost28147Mode::Ctr {
            gamma: [0u8; 24],
            feed,
            offset: 24,
        });
        Ok(())
    }

    /// `gost28147_encrypt` / `gost28147_decrypt` in CTR mode.
    pub fn ctr_crypt(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        if src.len() != dst.len() {
            return Err(Error::InvalidParam("ctr src/dst length mismatch".into()));
        }
        let Gost28147Mode::Ctr {
            gamma,
            feed,
            offset,
        } = self
            .mode
            .as_mut()
            .ok_or_else(|| Error::InvalidParam("gost28147 CTR not initialized".into()))?
        else {
            return Err(Error::InvalidParam("gost28147 not in CTR mode".into()));
        };
        ctr_crypt_core(src, dst, gamma, feed, offset, &self.key, &self.sbox);
        Ok(())
    }

    /// `gost28147_init_mac`.
    pub fn init_mac(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidParam(format!(
                "gost28147 key must be {KEY_LEN} bytes"
            )));
        }
        uint8_to_uint32(key, &mut self.key);
        self.mode = Some(Gost28147Mode::Mac {
            mac: [0u8; 8],
            offset: 0,
        });
        Ok(())
    }

    /// `gost28147_update_mac`.
    pub fn update_mac(&mut self, data: &[u8]) -> Result<()> {
        let Gost28147Mode::Mac { mac, offset } = self
            .mode
            .as_mut()
            .ok_or_else(|| Error::InvalidParam("gost28147 MAC not initialized".into()))?
        else {
            return Err(Error::InvalidParam("gost28147 not in MAC mode".into()));
        };
        mac_update_core(data, mac, offset, &self.key, &self.sbox);
        Ok(())
    }

    /// `gost28147_final_mac`: 4-byte MAC.
    pub fn final_mac(&mut self) -> Result<[u8; MAC_LEN]> {
        let Gost28147Mode::Mac { mac, offset } = self
            .mode
            .as_mut()
            .ok_or_else(|| Error::InvalidParam("gost28147 MAC not initialized".into()))?
        else {
            return Err(Error::InvalidParam("gost28147 not in MAC mode".into()));
        };
        if *offset != 0 {
            let mut mac32 = [0u32; 2];
            uint8_to_uint32(mac, &mut mac32);
            base_cycle8(
                &mut mac32,
                &self.key,
                &MAC_KEY_ORDER,
                16,
                &self.sbox,
            );
            uint32_to_uint8(&mac32, mac);
            *offset = 0;
        }
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&mac[..MAC_LEN]);
        *mac = [0u8; 8];
        Ok(out)
    }

    /// `gost28147_encrypt` / `gost28147_decrypt` (CFB mode).
    pub fn cfb_crypt(&mut self, src: &[u8], dst: &mut [u8], encrypt: bool) -> Result<()> {
        if src.len() != dst.len() {
            return Err(Error::InvalidParam("cfb src/dst length mismatch".into()));
        }
        let Gost28147Mode::Cfb {
            gamma,
            feed,
            offset,
        } = self
            .mode
            .as_mut()
            .ok_or_else(|| Error::InvalidParam("gost28147 CFB not initialized".into()))?
        else {
            return Err(Error::InvalidParam("gost28147 not in CFB mode".into()));
        };

        cfb_core(
            src,
            dst,
            encrypt,
            gamma,
            feed,
            offset,
            &self.key,
            &self.sbox,
        );
        Ok(())
    }

    fn inited_ecb(&self) -> Result<()> {
        if !matches!(self.mode, Some(Gost28147Mode::Ecb)) {
            return Err(Error::InvalidParam(
                "gost28147 context not initialized".into(),
            ));
        }
        Ok(())
    }

    /// `gost28147_ecb_core` encrypt path (`is_encrypt = true`).
    pub fn ecb_encrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        self.inited_ecb()?;
        if src.len() != dst.len() {
            return Err(Error::InvalidParam("ecb src/dst length mismatch".into()));
        }
        if src.len() % 8 != 0 {
            return Err(Error::InvalidParam(
                "ecb length must be multiple of 8".into(),
            ));
        }
        ecb_core(self, src, dst, true);
        Ok(())
    }

    /// Encrypt exactly one 8-byte block via `ecb_core` (used by DSTU PRNG).
    pub fn ecb_encrypt_block8(&self, block: &mut [u8; 8]) -> Result<()> {
        let src = *block;
        self.ecb_encrypt(&src, block)?;
        Ok(())
    }
}

/// `gost28147_wrap_key` (44-byte wrapped key).
pub fn wrap_key(
    sbox: &[u8; SBOX_LEN],
    kek: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    rng: &mut dyn RandomBytes,
) -> Result<[u8; WRAP_KEY_LEN]> {
    let mut ctx = Gost28147::from_raw_sbox(sbox);
    ctx.init_mac(kek)?;
    ctx.update_mac(key)?;
    let mac = ctx.final_mac()?;

    let mut iv = [0u8; IV_LEN];
    rng.fill(&mut iv)?;

    ctx.init_cfb(kek, &iv)?;
    let mut w_key = [0u8; WRAP_KEY_LEN];
    w_key[..IV_LEN].copy_from_slice(&iv);
    ctx.cfb_crypt(key, &mut w_key[IV_LEN..IV_LEN + KEY_LEN], true)?;
    ctx.cfb_crypt(&mac, &mut w_key[IV_LEN + KEY_LEN..], true)?;

    byte_swap(&mut w_key);

    ctx.init_cfb(kek, &IV_WRAP)?;
    let mut wrapped = [0u8; WRAP_KEY_LEN];
    ctx.cfb_crypt(&w_key, &mut wrapped, true)?;
    Ok(wrapped)
}

/// `gost28147_unwrap_key` (32-byte key).
pub fn unwrap_key(
    sbox: &[u8; SBOX_LEN],
    kek: &[u8; KEY_LEN],
    wrapped: &[u8; WRAP_KEY_LEN],
) -> Result<[u8; KEY_LEN]> {
    let mut ctx = Gost28147::from_raw_sbox(sbox);
    let mut dec = *wrapped;
    ctx.init_cfb(kek, &IV_WRAP)?;
    ctx.cfb_crypt(wrapped, &mut dec, false)?;
    byte_swap(&mut dec);

    let iv = &dec[..IV_LEN];
    ctx.init_cfb(kek, iv)?;
    let mut key = [0u8; KEY_LEN];
    ctx.cfb_crypt(&dec[IV_LEN..IV_LEN + KEY_LEN], &mut key, false)?;
    let mut mac = [0u8; MAC_LEN];
    ctx.cfb_crypt(&dec[IV_LEN + KEY_LEN..], &mut mac, false)?;

    ctx.init_mac(kek)?;
    ctx.update_mac(&key)?;
    let actual_mac = ctx.final_mac()?;
    if mac != actual_mac {
        return Err(Error::VerifyFailed);
    }
    Ok(key)
}

fn ecb_core(ctx: &Gost28147, src: &[u8], dst: &mut [u8], is_encrypt: bool) {
    let key_order = &ENCRYPT_KEY_ORDER;
    let mut off = 0usize;

    let full_blocks = src.len() / 24;
    for _ in 0..full_blocks {
        let mut block24 = [0u32; 6];
        uint8_to_uint32(&src[off..off + 24], &mut block24);
        base_cycle24(&mut block24, &ctx.key, key_order, &ctx.sbox);
        uint32_to_uint8(&block24, &mut dst[off..off + 24]);
        off += 24;
    }

    let remainder = src.len() % 24;
    if remainder != 0 {
        let mut block24 = [0u32; 6];
        let words = remainder / 4;
        uint8_to_uint32(&src[off..off + remainder], &mut block24[..words]);
        base_cycle24(&mut block24, &ctx.key, key_order, &ctx.sbox);
        uint32_to_uint8(&block24[..words], &mut dst[off..off + remainder]);
    }

    let _ = is_encrypt;
}

fn advance_gamma(
    feed: &[u8; 8],
    key: &[u32; 8],
    sbox: &[u32; 1024],
    gamma: &mut [u8; 8],
) {
    let mut gamma32 = [0u32; 2];
    uint8_to_uint32(feed, &mut gamma32);
    base_cycle8(&mut gamma32, key, &ENCRYPT_KEY_ORDER, 32, sbox);
    uint32_to_uint8(&gamma32, gamma);
}

fn advance_ctr_gamma(feed: &mut [u32; 6], key: &[u32; 8], sbox: &[u32; 1024], gamma: &mut [u8; 24]) {
    ctr_next_feed(feed);
    let mut block = *feed;
    base_cycle24(&mut block, key, &ENCRYPT_KEY_ORDER, sbox);
    uint32_to_uint8(&block, gamma);
}

fn ctr_crypt_core(
    src: &[u8],
    dst: &mut [u8],
    gamma: &mut [u8; 24],
    feed: &mut [u32; 6],
    offset: &mut usize,
    key: &[u32; 8],
    sbox: &[u32; 1024],
) {
    let mut data_off = 0usize;
    let len = src.len();

    if *offset != 0 {
        while *offset < 24 && data_off < len {
            dst[data_off] = src[data_off] ^ gamma[*offset];
            *offset += 1;
            data_off += 1;
        }
        if *offset == 24 {
            advance_ctr_gamma(feed, key, sbox, gamma);
            *offset = 0;
        }
    }

    while data_off + 24 <= len {
        for i in 0..24 {
            dst[data_off + i] = src[data_off + i] ^ gamma[i];
        }
        advance_ctr_gamma(feed, key, sbox, gamma);
        data_off += 24;
    }

    while data_off < len {
        dst[data_off] = src[data_off] ^ gamma[*offset];
        *offset += 1;
        data_off += 1;
    }
}

fn mac_advance(mac: &mut [u8; 8], key: &[u32; 8], sbox: &[u32; 1024]) {
    let mut mac32 = [0u32; 2];
    uint8_to_uint32(mac, &mut mac32);
    base_cycle8(&mut mac32, key, &MAC_KEY_ORDER, 16, sbox);
    uint32_to_uint8(&mac32, mac);
}

fn mac_update_core(
    src: &[u8],
    mac: &mut [u8; 8],
    offset: &mut usize,
    key: &[u32; 8],
    sbox: &[u32; 1024],
) {
    let mut data_off = 0usize;
    let len = src.len();

    if *offset != 0 {
        while *offset < 8 && data_off < len {
            mac[*offset] ^= src[data_off];
            *offset += 1;
            data_off += 1;
        }
        if *offset == 8 {
            mac_advance(mac, key, sbox);
            *offset = 0;
        }
    }

    while data_off + 8 <= len {
        for i in 0..8 {
            mac[i] ^= src[data_off + i];
        }
        mac_advance(mac, key, sbox);
        data_off += 8;
    }

    while data_off < len {
        mac[*offset] ^= src[data_off];
        *offset += 1;
        data_off += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn cfb_core(
    src: &[u8],
    dst: &mut [u8],
    encrypt: bool,
    gamma: &mut [u8; 8],
    feed: &mut [u8; 8],
    offset: &mut usize,
    key: &[u32; 8],
    sbox: &[u32; 1024],
) {
    let mut data_off = 0usize;
    let len = src.len();

    if *offset != 0 {
        if *offset == 8 {
            advance_gamma(feed, key, sbox, gamma);
            *offset = 0;
        } else {
            while *offset < 8 && data_off < len {
                if encrypt {
                    dst[data_off] = src[data_off] ^ gamma[*offset];
                    feed[*offset] = dst[data_off];
                } else {
                    feed[*offset] = src[data_off];
                    dst[data_off] = src[data_off] ^ gamma[*offset];
                }
                *offset += 1;
                data_off += 1;
            }
            if *offset == 8 {
                advance_gamma(feed, key, sbox, gamma);
                *offset = 0;
            }
        }
    }

    while data_off + 8 <= len {
        if encrypt {
            for i in 0..8 {
                dst[data_off + i] = src[data_off + i] ^ gamma[i];
            }
            feed.copy_from_slice(&dst[data_off..data_off + 8]);
        } else {
            feed.copy_from_slice(&src[data_off..data_off + 8]);
            for i in 0..8 {
                dst[data_off + i] = src[data_off + i] ^ gamma[i];
            }
        }
        advance_gamma(feed, key, sbox, gamma);
        data_off += 8;
    }

    while data_off < len {
        if encrypt {
            dst[data_off] = src[data_off] ^ gamma[*offset];
            feed[*offset] = dst[data_off];
        } else {
            feed[*offset] = src[data_off];
            dst[data_off] = src[data_off] ^ gamma[*offset];
        }
        *offset += 1;
        data_off += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dstu4145::SliceRandom;

    static GOST28147_SBOX_11: [u8; SBOX_LEN] = [
        0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5, 0x3, 0xe, 0xb,
        0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9, 0x5, 0x8, 0x1, 0xd,
        0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9, 0xb, 0x7, 0xd, 0xa, 0x1, 0x0, 0x8,
        0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5, 0x3, 0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8,
        0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb, 0x2, 0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6,
        0x8, 0x5, 0x9, 0xc, 0xf, 0xe, 0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7,
        0x6, 0x8, 0x2, 0xc, 0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb,
        0x8, 0xc,
    ];

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn cfb1_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let iv = hex("0300000003000000");
        let data = hex("0102030405060708090a0b0c0d0e0f101112131415161718");
        let enc_expected = hex("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3");

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_cfb(&key, &iv).unwrap();
        let mut enc = vec![0u8; data.len()];
        ctx.cfb_crypt(&data, &mut enc, true).unwrap();
        assert_eq!(enc, enc_expected);

        ctx.init_cfb(&key, &iv).unwrap();
        let mut dec = vec![0u8; enc.len()];
        ctx.cfb_crypt(&enc, &mut dec, false).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn cfb2_incremental_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let iv = hex("0300000003000000");
        let data1 = hex("0102030401020304010203040102030401020304010203040102030401020304");
        let data2 = hex("01020304");

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_cfb(&key, &iv).unwrap();
        let mut enc1 = vec![0u8; data1.len()];
        ctx.cfb_crypt(&data1, &mut enc1, true).unwrap();
        let mut enc2 = vec![0u8; data2.len()];
        ctx.cfb_crypt(&data2, &mut enc2, true).unwrap();

        ctx.init_cfb(&key, &iv).unwrap();
        let mut dec1 = vec![0u8; enc1.len()];
        ctx.cfb_crypt(&enc1, &mut dec1, false).unwrap();
        let mut dec2 = vec![0u8; enc2.len()];
        ctx.cfb_crypt(&enc2, &mut dec2, false).unwrap();
        assert_eq!(dec1, data1);
        assert_eq!(dec2, data2);
    }

    #[test]
    fn ecb_encrypt_8_bytes_sbox1_matches_cryptonite() {
        let key = [
            0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67, 0x15, 0x3d, 0xde, 0x59, 0x33, 0x88,
            0x42, 0x50, 0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c, 0x1c, 0x9c, 0xa0, 0x9a,
            0x56, 0xd9, 0x68, 0xcf,
        ];
        let input = [0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56];
        let expected = [0xa9, 0x5b, 0x64, 0x5d, 0xe3, 0xa9, 0xb5, 0x47];

        let mut ctx = Gost28147::new();
        ctx.init_ecb(&key).unwrap();
        let mut out = [0u8; 8];
        ctx.ecb_encrypt(&input, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn ecb_encrypt_24_bytes_sbox1_matches_cryptonite() {
        let key = [
            0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67, 0x15, 0x3d, 0xde, 0x59, 0x33, 0x88,
            0x42, 0x50, 0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c, 0x1c, 0x9c, 0xa0, 0x9a,
            0x56, 0xd9, 0x68, 0xcf,
        ];
        let input = [
            0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56, 0xe9, 0x43, 0x16, 0x04, 0xf5, 0x7e,
            0x37, 0xa1, 0x8f, 0x90, 0xeb, 0x03, 0x33, 0xa3, 0x33, 0x62,
        ];
        let mut ctx = Gost28147::new();
        ctx.init_ecb(&key).unwrap();
        let mut out = [0u8; 24];
        ctx.ecb_encrypt(&input, &mut out).unwrap();
        let expected = [
            0xa9, 0x5b, 0x64, 0x5d, 0xe3, 0xa9, 0xb5, 0x47, 0x42, 0xcb, 0x3b, 0x69, 0xe0, 0x50,
            0xdd, 0x68, 0x49, 0x95, 0x42, 0x2e, 0x67, 0xd7, 0x4e, 0xd4,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn mac_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let data = hex("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3");
        let mac_exp = hex("7e4a9667");

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_mac(&key).unwrap();
        ctx.update_mac(&data).unwrap();
        let mac = ctx.final_mac().unwrap();
        assert_eq!(mac.as_slice(), mac_exp);
    }

    #[test]
    fn ctr_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let iv = hex("0300000003000000");
        let data = hex("0102030405060708090a0b0c0d0e0f101112131415161718");
        let enc_expected = hex("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_ctr(&key, &iv).unwrap();
        let mut enc = vec![0u8; data.len()];
        ctx.ctr_crypt(&data, &mut enc).unwrap();
        assert_eq!(enc, enc_expected);

        ctx.init_ctr(&key, &iv).unwrap();
        let mut dec = vec![0u8; enc.len()];
        ctx.ctr_crypt(&enc, &mut dec).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn ctr_incremental_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let iv = hex("0300000003000000");
        let data1 = hex("010203");
        let data2 = hex("0405060708090a0b0c0d0e0f101112131415161718");
        let enc_expected = hex("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_ctr(&key, &iv).unwrap();
        let mut enc1 = vec![0u8; data1.len()];
        ctx.ctr_crypt(&data1, &mut enc1).unwrap();
        let mut enc2 = vec![0u8; data2.len()];
        ctx.ctr_crypt(&data2, &mut enc2).unwrap();
        let mut enc = enc1;
        enc.extend_from_slice(&enc2);
        assert_eq!(enc, enc_expected);
    }

    #[test]
    fn ctr_long_matches_cryptonite_utest() {
        let key = hex("0100000002000000030000000400000005000000060000000700000008000000");
        let iv = hex("0300000003000000");
        let data = hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
        );
        let enc_expected = hex(
            "da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f40bd18016490ddff6e446981c559778e4273350c755e2113dd8c2533450b2d481d004af84b8daa2cc",
        );

        let mut ctx = Gost28147::from_raw_sbox(&GOST28147_SBOX_11);
        ctx.init_ctr(&key, &iv).unwrap();
        let mut enc = vec![0u8; data.len()];
        ctx.ctr_crypt(&data, &mut enc).unwrap();
        assert_eq!(enc, enc_expected);
    }

    #[test]
    fn compress_sbox_roundtrips_expand_dke() {
        let dke = compress_sbox(&GOST28147_SBOX_11);
        let expanded = expand_dke(&dke).unwrap();
        assert_eq!(expanded, GOST28147_SBOX_11);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = [
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
        ];
        let key = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x01,
        ];
        let mut rng = SliceRandom::new([0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
        let wrapped = wrap_key(&GOST28147_SBOX_11, &kek, &key, &mut rng).unwrap();
        let unwrapped = unwrap_key(&GOST28147_SBOX_11, &kek, &wrapped).unwrap();
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn unwrap_rejects_bad_mac() {
        let kek = [0u8; KEY_LEN];
        let key = [0xab; KEY_LEN];
        let mut rng = SliceRandom::new([0u8; 8]);
        let sbox = default_sbox();
        let mut wrapped = wrap_key(&sbox, &kek, &key, &mut rng).unwrap();
        wrapped[WRAP_KEY_LEN - 1] ^= 0xff;
        assert!(unwrap_key(&sbox, &kek, &wrapped).is_err());
    }
}
