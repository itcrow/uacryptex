//! Kupyna compression functions (from `kupyna` 0.1.0, S-box 1) for Cryptonite-compatible streaming.

mod consts;
mod long;
mod short;
mod table;
pub mod utils;

pub use long::{compress as compress_long, t_xor_l as t_xor_l_long, COLS as COLS_LONG};
pub use short::{compress as compress_short, t_xor_l as t_xor_l_short, COLS as COLS_SHORT};
