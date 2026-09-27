//! CLI flags → env snapshot at startup, driven by `.cli-flags.toml` via
//! flags-2-env (github.com/ORESoftware/flags-2-env).
//!
//! The implementation lives in [`crate::env_map`]. Callers receive an ordinary
//! map; this never writes the process environment.

pub use crate::env_map::*;
