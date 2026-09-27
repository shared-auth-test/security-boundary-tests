use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

pub const MAX_STATIC_ATOMS_PER_MODULE: u32 = 4_096;
pub const MAX_STATIC_ATOMS_PER_ARTIFACT: u32 = 16_384;

pub fn verify_static_atom_budget(beam_dir: &Path) -> Result<u32> {
    let mut total = 0_u32;
    let mut found = false;
    for entry in fs::read_dir(beam_dir)
        .with_context(|| format!("read BEAM directory {}", beam_dir.display()))?
    {
        let entry = entry.with_context(|| format!("enumerate {}", beam_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("beam") {
            continue;
        }
        found = true;
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let count = atom_count(&bytes)
            .with_context(|| format!("inspect static atoms in {}", path.display()))?;
        if count > MAX_STATIC_ATOMS_PER_MODULE {
            bail!(
                "BEAM module {} contains {count} static atoms; maximum is {MAX_STATIC_ATOMS_PER_MODULE}",
                path.display()
            );
        }
        total = total
            .checked_add(count)
            .context("static atom count overflow")?;
        if total > MAX_STATIC_ATOMS_PER_ARTIFACT {
            bail!(
                "BEAM artifact contains {total} static atoms; maximum is {MAX_STATIC_ATOMS_PER_ARTIFACT}"
            );
        }
    }
    if !found {
        bail!("artifact contains no BEAM modules");
    }
    Ok(total)
}

pub fn atom_count(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 12 || &bytes[0..4] != b"FOR1" || &bytes[8..12] != b"BEAM" {
        bail!("invalid BEAM header");
    }
    let declared = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if declared != bytes.len() - 8 {
        bail!("invalid FOR1 size");
    }

    let mut offset = 12_usize;
    let mut seen = None;
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            bail!("truncated BEAM chunk header");
        }
        let id = &bytes[offset..offset + 4];
        let size = u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        let padded = size
            .checked_add((4 - (size % 4)) % 4)
            .context("BEAM chunk size overflow")?;
        if bytes.len() - offset < padded {
            bail!("truncated BEAM chunk");
        }
        if id == b"AtU8" || id == b"Atom" {
            if seen.is_some() {
                bail!("multiple BEAM atom chunks");
            }
            if size < 4 {
                bail!("truncated BEAM atom chunk");
            }
            let raw = bytes[offset..offset + 4].try_into().unwrap();
            seen = Some(decode_atom_count(id, raw)?);
        }
        offset += padded;
    }
    seen.context("missing BEAM atom chunk")
}

fn decode_atom_count(id: &[u8], raw: [u8; 4]) -> Result<u32> {
    let signed = i32::from_be_bytes(raw);
    if id == b"AtU8" && signed < 0 {
        // OTP 28+ kept the AtU8 chunk name but changed its encoding. A negative
        // signed count marks the long-atom encoding; the atom count is its
        // absolute value. For example 0xFFFFFFFB is -5 and therefore 5 atoms.
        let count = signed
            .checked_neg()
            .context("invalid OTP 28+ AtU8 atom count")?;
        return u32::try_from(count).context("invalid OTP 28+ AtU8 atom count");
    }
    if signed < 0 {
        bail!("negative atom count in legacy Atom chunk");
    }
    Ok(signed as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn beam_with_raw_atom_count(id: &[u8; 4], raw_count: [u8; 4]) -> Vec<u8> {
        let chunk_len = 8 + raw_count.len();
        let declared = (4 + chunk_len) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(b"FOR1");
        out.extend_from_slice(&declared.to_be_bytes());
        out.extend_from_slice(b"BEAM");
        out.extend_from_slice(id);
        out.extend_from_slice(&(raw_count.len() as u32).to_be_bytes());
        out.extend_from_slice(&raw_count);
        out
    }

    fn beam_with_atoms(id: &[u8; 4], count: u32) -> Vec<u8> {
        beam_with_raw_atom_count(id, count.to_be_bytes())
    }

    fn modern_atu8(count: u32) -> Vec<u8> {
        let signed = i32::try_from(count).expect("test count fits signed AtU8 range");
        beam_with_raw_atom_count(b"AtU8", (-signed).to_be_bytes())
    }

    #[test]
    fn parses_utf8_and_legacy_atom_chunks() {
        assert_eq!(atom_count(&beam_with_atoms(b"AtU8", 42)).unwrap(), 42);
        assert_eq!(atom_count(&beam_with_atoms(b"Atom", 7)).unwrap(), 7);
    }

    #[test]
    fn parses_otp_28_plus_negative_atu8_count() {
        assert_eq!(atom_count(&modern_atu8(5)).unwrap(), 5);
        assert_eq!(atom_count(&modern_atu8(4096)).unwrap(), 4096);
    }

    #[test]
    fn rejects_negative_legacy_atom_count() {
        assert!(atom_count(&beam_with_raw_atom_count(b"Atom", (-5_i32).to_be_bytes())).is_err());
    }

    #[test]
    fn rejects_malformed_beam() {
        assert!(atom_count(b"not-beam").is_err());
    }

    #[test]
    fn rejects_per_module_budget() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("worker.beam"),
            modern_atu8(MAX_STATIC_ATOMS_PER_MODULE + 1),
        )
        .unwrap();
        assert!(verify_static_atom_budget(dir.path()).is_err());
    }

    #[test]
    fn rejects_per_artifact_budget() {
        let dir = tempdir().unwrap();
        for n in 0..5 {
            fs::write(
                dir.path().join(format!("m{n}.beam")),
                modern_atu8(MAX_STATIC_ATOMS_PER_MODULE),
            )
            .unwrap();
        }
        assert!(verify_static_atom_budget(dir.path()).is_err());
    }
}
