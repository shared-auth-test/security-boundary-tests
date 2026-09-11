#![forbid(unsafe_code)]

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const DEV_RULE: &str = r"^env/enc/dev\.env\.enc$";
const PROD_RULE: &str = r"^env/enc/prod\.env\.enc$";
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Debug, Deserialize)]
struct SopsConfig {
    #[serde(default)]
    creation_rules: Vec<CreationRule>,
}

#[derive(Debug, Deserialize)]
struct CreationRule {
    path_regex: String,
    #[serde(default)]
    age: Vec<String>,
}

fn bech32_polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GENERATORS: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if ((top >> index) & 1) == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn bech32_hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|byte| byte & 0x1f))
}

fn decode_age_recipient(recipient: &str) -> Result<Vec<u8>, String> {
    if recipient.is_empty()
        || recipient.bytes().any(|byte| !(33..=126).contains(&byte))
        || recipient != recipient.to_ascii_lowercase()
    {
        return Err("recipient must be lowercase printable Bech32".to_owned());
    }
    let separator = recipient
        .rfind('1')
        .ok_or_else(|| "recipient has no Bech32 separator".to_owned())?;
    let (hrp, encoded) = recipient.split_at(separator);
    let encoded = &encoded[1..];
    if hrp != "age" {
        return Err("recipient Bech32 human-readable prefix must be age".to_owned());
    }
    if encoded.len() < 7 {
        return Err("recipient Bech32 payload is too short".to_owned());
    }

    let mut values = Vec::with_capacity(encoded.len());
    for byte in encoded.bytes() {
        let value = BECH32_CHARSET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| "recipient contains a non-Bech32 character".to_owned())?;
        values.push(value as u8);
    }
    if bech32_polymod(bech32_hrp_expand(hrp).chain(values.iter().copied())) != 1 {
        return Err("recipient has an invalid Bech32 checksum".to_owned());
    }

    let payload = &values[..values.len() - 6];
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut decoded = Vec::new();
    for value in payload {
        accumulator = (accumulator << 5) | u32::from(*value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            decoded.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && ((accumulator << (8 - bits)) & 0xff) != 0 {
        return Err("recipient has non-zero Bech32 padding".to_owned());
    }
    if decoded.len() != 32 {
        return Err(format!(
            "recipient must encode exactly 32 X25519 public-key bytes, got {}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn parse_recipients(path: &Path) -> Result<BTreeMap<&'static str, BTreeSet<String>>, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let config: SopsConfig = serde_yaml::from_str(&source)
        .map_err(|error| format!("invalid SOPS YAML {}: {error}", path.display()))?;

    let mut recipients = BTreeMap::from([("dev", BTreeSet::new()), ("prod", BTreeSet::new())]);
    let mut seen = BTreeSet::new();

    for rule in config.creation_rules {
        let environment = match rule.path_regex.as_str() {
            DEV_RULE => Some("dev"),
            PROD_RULE => Some("prod"),
            _ => None,
        };
        let Some(environment) = environment else {
            continue;
        };
        if !seen.insert(environment) {
            return Err(format!("duplicate {environment} SOPS creation rule"));
        }
        if rule.age.is_empty() {
            return Err(format!("{environment} SOPS rule has no age recipients"));
        }
        for recipient in rule.age {
            decode_age_recipient(&recipient).map_err(|reason| {
                format!(
                    "{environment} SOPS rule contains an invalid public age recipient: {reason}"
                )
            })?;
            if !recipients
                .get_mut(environment)
                .expect("known environment")
                .insert(recipient)
            {
                return Err(format!(
                    "{environment} SOPS rule contains a duplicate age recipient"
                ));
            }
        }
    }

    if !seen.contains("dev") || !seen.contains("prod") {
        return Err("both exact dev and prod SOPS creation rules are required".to_owned());
    }
    Ok(recipients)
}

fn validate(path: &Path, environment: &str) -> Result<Option<(usize, usize)>, String> {
    let recipients = parse_recipients(path)?;
    match environment.to_ascii_lowercase().as_str() {
        "dev" => return Ok(None),
        "prod" => {}
        _ => return Err("environment must be exactly dev or prod".to_owned()),
    }

    let dev = recipients.get("dev").expect("dev recipient set");
    let prod = recipients.get("prod").expect("prod recipient set");
    if dev.is_empty() {
        return Err("development SOPS recipient set is empty".to_owned());
    }
    if prod.len() < 2 {
        return Err("production SOPS policy requires at least two recipients".to_owned());
    }
    if prod == dev {
        return Err("production and development recipient sets must differ".to_owned());
    }
    if prod.difference(dev).next().is_none() {
        return Err(
            "production SOPS policy needs a recipient not present in development".to_owned(),
        );
    }
    Ok(Some((dev.len(), prod.len())))
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: shared-auth-sops-release-policy <.sops.yaml> <environment>");
        return ExitCode::from(2);
    };
    let Some(environment) = args.next() else {
        eprintln!("usage: shared-auth-sops-release-policy <.sops.yaml> <environment>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: shared-auth-sops-release-policy <.sops.yaml> <environment>");
        return ExitCode::from(2);
    }

    match validate(Path::new(&path), &environment) {
        Ok(Some((dev, prod))) => {
            println!(
                "production SOPS policy verified (dev recipients={dev}, prod recipients={prod})"
            );
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("invalid SOPS recipient policy: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const RECIPIENT_A: &str = "age1qrnva7lnv2jzww6ah5au0cqm4wkvkm5shpzflekdcm4nlu6wnyfqgfaxft";
    const RECIPIENT_B: &str = "age1txv6jzlds2s03advmdtnm5l93qh4rkqs50nwvzk9yfvsartzue8se8t7jv";
    const RECIPIENT_C: &str = "age1s8lcnaxn9g77s6j4g7p24w6sgvllpue0lzrsvp3xk02k2gwjj5ssnkp39q";

    fn write_fixture(source: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temporary file");
        file.write_all(source.as_bytes()).expect("write fixture");
        file
    }

    fn valid_fixture(dev: &[&str], prod: &[&str]) -> tempfile::NamedTempFile {
        let dev = dev
            .iter()
            .map(|recipient| format!("      - {recipient}"))
            .collect::<Vec<_>>()
            .join("\n");
        let prod = prod
            .iter()
            .map(|recipient| format!("      - {recipient}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_fixture(&format!(
            "creation_rules:\n  - path_regex: ^env/enc/dev\\.env\\.enc$\n    age:\n{dev}\n  - path_regex: ^env/enc/prod\\.env\\.enc$\n    age:\n{prod}\n"
        ))
    }

    #[test]
    fn repository_policy_passes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(
            validate(&root.join(".sops.yaml"), "prod").expect("valid policy"),
            Some((2, 2))
        );
    }

    #[test]
    fn malformed_yaml_is_rejected_instead_of_regex_scanned() {
        let fixture = write_fixture(
            "creation_rules:\n  - path_regex: \"^env/enc/dev\\.env\\.enc$\"\n    age:\n      - age1abcdefghijklmnopqrstuvwxyz\n",
        );
        let error = validate(fixture.path(), "prod").expect_err("must reject invalid YAML");
        assert!(error.contains("invalid SOPS YAML"));
    }

    #[test]
    fn production_requires_an_independent_recipient() {
        let fixture = valid_fixture(&[RECIPIENT_A, RECIPIENT_B], &[RECIPIENT_A, RECIPIENT_B]);
        let error = validate(fixture.path(), "prod").expect_err("must reject weak policy");
        assert!(error.contains("must differ"));
    }

    #[test]
    fn invalid_bech32_checksum_is_rejected() {
        let mut invalid = RECIPIENT_A.to_owned();
        invalid.pop();
        invalid.push('q');
        let fixture = valid_fixture(&[&invalid, RECIPIENT_B], &[RECIPIENT_B, RECIPIENT_C]);
        let error = validate(fixture.path(), "prod").expect_err("checksum must fail");
        assert!(error.contains("checksum"));
    }

    #[test]
    fn non_bech32_characters_are_rejected() {
        let invalid = "age1!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        let fixture = valid_fixture(&[invalid, RECIPIENT_B], &[RECIPIENT_B, RECIPIENT_C]);
        let error = validate(fixture.path(), "prod").expect_err("charset must fail");
        assert!(error.contains("non-Bech32"));
    }

    #[test]
    fn duplicate_recipients_are_rejected_explicitly() {
        let fixture = valid_fixture(&[RECIPIENT_A, RECIPIENT_A], &[RECIPIENT_B, RECIPIENT_C]);
        let error = validate(fixture.path(), "prod").expect_err("duplicates must fail");
        assert!(error.contains("duplicate age recipient"));
    }

    #[test]
    fn malformed_yaml_is_not_skipped_for_dev() {
        let fixture = write_fixture("creation_rules: [unterminated");
        let error = validate(fixture.path(), "dev").expect_err("dev must parse config");
        assert!(error.contains("invalid SOPS YAML"));
    }

    #[test]
    fn mistyped_environment_is_rejected() {
        let fixture = valid_fixture(&[RECIPIENT_A, RECIPIENT_B], &[RECIPIENT_B, RECIPIENT_C]);
        let error = validate(fixture.path(), "prd").expect_err("typo must fail");
        assert!(error.contains("exactly dev or prod"));
    }

    #[test]
    fn decoded_age_payload_is_exactly_x25519_length() {
        assert_eq!(decode_age_recipient(RECIPIENT_A).unwrap().len(), 32);
    }
}
