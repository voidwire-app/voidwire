//! voidwire-sign: the update signing tool (docs/UPDATES.md).
//!
//! ```text
//! voidwire-sign keygen [--out FILE]        new passphrase-protected key file
//! voidwire-sign keygen --ci                new raw key on stdout (for a CI secret)
//! voidwire-sign pubkey FILE                print the public key line
//! voidwire-sign sign --key FILE MANIFEST   write MANIFEST.sig (asks the passphrase)
//! voidwire-sign sign --key-env VAR MANIFEST
//! voidwire-sign verify --channel test|stable MANIFEST [SIG]
//! voidwire-sign verify --pub LINE MANIFEST [SIG]
//! ```
//!
//! The passphrase is read from the terminal, or from
//! `VOIDWIRE_SIGN_PASSPHRASE` when set (scripts and tests).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};
use voidwire_core::hex;
use voidwire_core::update::sig;
use voidwire_core::update::{keys, Channel};
use zeroize::Zeroizing;

const KEY_HEADER: &str = "voidwire-update-key-v1";
// Argon2id, 64 MiB, 3 passes: a few hundred ms on a laptop.
const KDF_M_KIB: u32 = 64 * 1024;
const KDF_T: u32 = 3;
const KDF_P: u32 = 1;
const MIN_PASSPHRASE: usize = 12;

/// The error `main` returns: Rust prints it as `Error: <message>` and exits
/// with status 1.
struct Failure(String);

impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args).map_err(Failure)
}

const USAGE: &str = "usage:
  voidwire-sign keygen [--out FILE]
  voidwire-sign keygen --ci
  voidwire-sign pubkey FILE
  voidwire-sign sign (--key FILE | --key-env VAR) MANIFEST [--out SIG]
  voidwire-sign verify (--channel test|stable | --pub LINE) MANIFEST [SIG]";

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or(USAGE)?;
    let mut opts = Opts::parse(rest)?;
    match cmd.as_str() {
        "keygen" if opts.flag("--ci") => keygen_ci(),
        "keygen" => keygen(
            &opts
                .value("--out")
                .unwrap_or_else(|| "voidwire-update.key".into()),
        ),
        "pubkey" => {
            let f = opts.positional(0).ok_or(USAGE)?;
            println!("{}", read_key_file(Path::new(&f))?.0.to_line());
            Ok(())
        }
        "sign" => sign_cmd(&mut opts),
        "verify" => verify_cmd(&mut opts),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

struct Opts {
    named: Vec<(String, Option<String>)>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Opts, String> {
        let mut named = Vec::new();
        let mut positional = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--ci" => named.push((a.clone(), None)),
                "--out" | "--key" | "--key-env" | "--channel" | "--pub" => {
                    let v = it.next().ok_or(format!("{a} needs a value"))?;
                    named.push((a.clone(), Some(v.clone())));
                }
                s if s.starts_with("--") => return Err(format!("unknown option {s}\n{USAGE}")),
                _ => positional.push(a.clone()),
            }
        }
        Ok(Opts { named, positional })
    }

    fn flag(&self, n: &str) -> bool {
        self.named.iter().any(|(k, _)| k == n)
    }

    fn value(&self, n: &str) -> Option<String> {
        self.named
            .iter()
            .find(|(k, _)| k == n)
            .and_then(|(_, v)| v.clone())
    }

    fn positional(&self, i: usize) -> Option<String> {
        self.positional.get(i).cloned()
    }
}

fn passphrase(prompt: &str) -> Result<Zeroizing<String>, String> {
    if let Ok(p) = std::env::var("VOIDWIRE_SIGN_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("couldn't read the passphrase: {e}"))
}

fn kdf(pass: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params =
        argon2::Params::new(KDF_M_KIB, KDF_T, KDF_P, Some(32)).map_err(|e| e.to_string())?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), salt, &mut *out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn aad(pub_hex: &str) -> Vec<u8> {
    format!("{KEY_HEADER}\n{pub_hex}").into_bytes()
}

/// The key file: the public key in the clear, the seed sealed with
/// XChaCha20-Poly1305 under an Argon2id key from the passphrase.
fn encode_key_file(seed: &[u8; 32], pass: &str) -> Result<String, String> {
    let pk = sig::public_key(seed);
    let pub_hex = hex::encode(&pk.to_bytes());
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let k = kdf(pass, &salt)?;
    let sealed = XChaCha20Poly1305::new((&*k).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: &aad(&pub_hex),
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    Ok(format!(
        "{KEY_HEADER}\npub {pub_hex}\nkdf argon2id m={KDF_M_KIB} t={KDF_T} p={KDF_P}\nsalt {}\nnonce {}\nsealed {}\n",
        hex::encode(&salt),
        hex::encode(&nonce),
        hex::encode(&sealed)
    ))
}

struct KeyFile {
    pub_hex: String,
    m: u32,
    t: u32,
    p: u32,
    salt: [u8; 16],
    nonce: [u8; 24],
    sealed: Vec<u8>,
}

fn parse_key_file(text: &str) -> Result<KeyFile, String> {
    let bad = || "not a voidwire-sign key file".to_string();
    let mut lines = text.lines();
    if lines.next() != Some(KEY_HEADER) {
        return Err(bad());
    }
    let mut field = |name: &str| -> Result<String, String> {
        let l = lines.next().ok_or_else(bad)?;
        l.strip_prefix(name)
            .and_then(|r| r.strip_prefix(' '))
            .map(str::to_owned)
            .ok_or_else(bad)
    };
    let pub_hex = field("pub")?;
    let kdf = field("kdf")?;
    let salt = hex::decode_array::<16>(&field("salt")?).ok_or_else(bad)?;
    let nonce = hex::decode_array::<24>(&field("nonce")?).ok_or_else(bad)?;
    let sealed_hex = field("sealed")?;
    if sealed_hex.len() != 96 {
        return Err(bad());
    }
    let sealed = hex::decode_array::<48>(&sealed_hex)
        .ok_or_else(bad)?
        .to_vec();
    let mut it = kdf.split(' ');
    if it.next() != Some("argon2id") {
        return Err(bad());
    }
    let mut num = |k: &str| -> Result<u32, String> {
        it.next()
            .and_then(|s| s.strip_prefix(k))
            .and_then(|s| s.parse().ok())
            .ok_or_else(bad)
    };
    let (m, t, p) = (num("m=")?, num("t=")?, num("p=")?);
    Ok(KeyFile {
        pub_hex,
        m,
        t,
        p,
        salt,
        nonce,
        sealed,
    })
}

fn read_key_file(path: &Path) -> Result<(sig::PublicKey, KeyFile), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("can't read {}: {e}", path.display()))?;
    let kf = parse_key_file(&text)?;
    let pk = hex::decode_array::<32>(&kf.pub_hex)
        .and_then(|b| sig::PublicKey::from_bytes(&b))
        .ok_or("bad public key in the key file")?;
    Ok((pk, kf))
}

fn open_key_file(kf: &KeyFile, pass: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let params =
        argon2::Params::new(kf.m, kf.t, kf.p, Some(32)).map_err(|_| "bad KDF parameters")?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut k = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), &kf.salt, &mut *k)
        .map_err(|e| e.to_string())?;
    let seed = XChaCha20Poly1305::new((&*k).into())
        .decrypt(
            XNonce::from_slice(&kf.nonce),
            Payload {
                msg: &kf.sealed,
                aad: &aad(&kf.pub_hex),
            },
        )
        .map_err(|_| "wrong passphrase (or a damaged key file)".to_string())?;
    let seed = Zeroizing::new(seed);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&seed);
    if hex::encode(&sig::public_key(&out).to_bytes()) != kf.pub_hex {
        return Err("key file does not match its public key".into());
    }
    Ok(out)
}

fn keygen(out: &str) -> Result<(), String> {
    let path = PathBuf::from(out);
    if path.exists() {
        return Err(format!("{} exists; not overwriting a key", path.display()));
    }
    let p1 = passphrase("New passphrase (12+ characters): ")?;
    if p1.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "the passphrase needs at least {MIN_PASSPHRASE} characters"
        ));
    }
    if std::env::var_os("VOIDWIRE_SIGN_PASSPHRASE").is_none() {
        let p2 = passphrase("Same passphrase again: ")?;
        if *p1 != *p2 {
            return Err("the passphrases differ".into());
        }
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    let text = encode_key_file(&seed, &p1)?;
    write_new(&path, text.as_bytes())?;
    let pk = sig::public_key(&seed);
    eprintln!(
        "Wrote {}. Keep it offline and back it up; it can't be recovered.",
        path.display()
    );
    eprintln!("Public key (send this line; it goes into core/src/update/keys.rs):");
    println!("{}", pk.to_line());
    Ok(())
}

/// A fresh raw key for a CI secret: the hex seed on stdout (pipe it straight
/// into `gh secret set`), the public key line on stderr. Nothing on disk.
fn keygen_ci() -> Result<(), String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    eprintln!("{}", sig::public_key(&seed).to_line());
    print!("{}", Zeroizing::new(hex::encode(&*seed)).as_str());
    Ok(())
}

fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|e| format!("can't create {}: {e}", path.display()))?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("can't write {}: {e}", path.display()))
}

/// A short summary of the manifest about to be signed, after basic checks.
fn describe(manifest: &[u8]) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|e| format!("manifest is not JSON: {e}"))?;
    if v["schema"] != 1 {
        return Err("manifest schema is not 1".into());
    }
    let ch = v["channel"].as_str().ok_or("manifest has no channel")?;
    if ch != "test" && ch != "stable" {
        return Err(format!("unknown channel {ch}"));
    }
    let files = v["files"].as_object().ok_or("manifest has no files")?;
    let mut s = format!(
        "channel {ch}, version {}, build {}, seq {}",
        v["version"].as_str().unwrap_or("?"),
        v["build"],
        v["seq"]
    );
    for (k, f) in files {
        s.push_str(&format!(
            "\n  {k}: {} bytes, sha256 {}\n    {}",
            f["size"],
            f["sha256"].as_str().unwrap_or("?"),
            f["url"].as_str().unwrap_or("?")
        ));
    }
    Ok(s)
}

fn sign_cmd(opts: &mut Opts) -> Result<(), String> {
    let manifest_path = PathBuf::from(opts.positional(0).ok_or(USAGE)?);
    let manifest = std::fs::read(&manifest_path)
        .map_err(|e| format!("can't read {}: {e}", manifest_path.display()))?;
    let summary = describe(&manifest)?;
    let seed = if let Some(var) = opts.value("--key-env") {
        let v = Zeroizing::new(std::env::var(&var).map_err(|_| format!("{var} is not set"))?);
        Zeroizing::new(hex::decode_array::<32>(v.trim()).ok_or(format!("{var} is not a key"))?)
    } else if let Some(f) = opts.value("--key") {
        let (_, kf) = read_key_file(Path::new(&f))?;
        eprintln!("Signing {}:\n{summary}", manifest_path.display());
        let p = passphrase("Passphrase: ")?;
        open_key_file(&kf, &p)?
    } else {
        return Err(USAGE.into());
    };
    let line = sig::sign(&seed, &manifest);
    let out = opts
        .value("--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| sig_path(&manifest_path));
    let _ = std::fs::remove_file(&out);
    write_new(&out, line.as_bytes())?;
    eprintln!(
        "Wrote {} (key {}).",
        out.display(),
        hex::encode(&sig::public_key(&seed).key_id())
    );
    Ok(())
}

fn sig_path(manifest: &Path) -> PathBuf {
    let mut s = manifest.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

fn verify_cmd(opts: &mut Opts) -> Result<(), String> {
    let manifest_path = PathBuf::from(opts.positional(0).ok_or(USAGE)?);
    let sig_file = opts
        .positional(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| sig_path(&manifest_path));
    let manifest = std::fs::read(&manifest_path)
        .map_err(|e| format!("can't read {}: {e}", manifest_path.display()))?;
    let sig_text = std::fs::read_to_string(&sig_file)
        .map_err(|e| format!("can't read {}: {e}", sig_file.display()))?;
    let keys = match (opts.value("--channel").as_deref(), opts.value("--pub")) {
        (Some("test"), None) => keys::pinned(Channel::Test),
        (Some("stable"), None) => keys::pinned(Channel::Stable),
        (None, Some(line)) => vec![sig::PublicKey::parse(&line).ok_or("bad --pub line")?],
        _ => return Err(USAGE.into()),
    };
    let summary = describe(&manifest)?;
    if let Some(ch) = opts.value("--channel") {
        let v: serde_json::Value = serde_json::from_slice(&manifest).map_err(|e| e.to_string())?;
        if v["channel"].as_str() != Some(ch.as_str()) {
            return Err(format!(
                "manifest is for channel {}, not {ch}",
                v["channel"]
            ));
        }
    }
    let k = sig::verify(&keys, &manifest, &sig_text).map_err(|e| e.to_string())?;
    println!("OK: signed by key {}\n{summary}", hex::encode(&k.key_id()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_round_trip() {
        let seed = [5u8; 32];
        let text = encode_key_file(&seed, "correct horse battery").unwrap();
        assert!(
            !text.contains(&hex::encode(&seed)),
            "seed never in the clear"
        );
        let kf = parse_key_file(&text).unwrap();
        assert_eq!(*open_key_file(&kf, "correct horse battery").unwrap(), seed);
        assert!(open_key_file(&kf, "wrong horse battery").is_err());
        // Swapping the public key line breaks the seal (AAD).
        let other = hex::encode(&sig::public_key(&[6; 32]).to_bytes());
        let swapped = text.replace(&kf.pub_hex, &other);
        let kf2 = parse_key_file(&swapped).unwrap();
        assert!(open_key_file(&kf2, "correct horse battery").is_err());
    }

    #[test]
    fn describe_checks_shape() {
        assert!(describe(b"{}").is_err());
        assert!(describe(br#"{"schema":1,"channel":"beta","files":{}}"#).is_err());
        let d = describe(
            br#"{"schema":1,"channel":"test","version":"1","build":2,"seq":3,"files":{}}"#,
        )
        .unwrap();
        assert!(d.contains("channel test"));
    }
}
