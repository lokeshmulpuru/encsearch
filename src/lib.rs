//! encsearch: searchable encryption for PostgreSQL.
//!
//! Values are encrypted with an AEAD cipher (AES-256-GCM by default; see ALGS).
//! Alongside each value we store a "blind index": 64-bit truncated HMAC-SHA256
//! (or keyed BLAKE3, see encsearch.token_hash) tokens of the normalized
//! (lowercased) text. Queries hash their search terms with the same key and match
//! tokens via a GIN index on the int8[] column, so no row is decrypted to search.
//!
//! Token kinds (each hash input is prefixed with a one-byte tag):
//!   'x' whole value       -> exact match
//!   'w' each word         -> word search
//!   't' each trigram of   -> prefix / suffix / substring (LIKE) search
//!   'b' each bigram of    -> short (1-2 char) LIKE segments
//!       \x02 + text + \x03    (markers anchor the start and end)
//!
//! The index is a superset filter (case-insensitive, n-gram based), so queries
//! recheck candidates with enc_decrypt(...) to get exact semantics. The
//! enc_like / enc_ilike / enc_eq helpers do both steps and still use the index.
//!
//! Keys: every function takes the key as its last argument, or omit it to use
//! the session key set with `SET encsearch.key = '...'`. Keys must be at least
//! 32 characters; enc_gen_key() makes a random one.
//!
//! WARNING: experimental. The blind index leaks equality, word frequency and
//! n-gram patterns to anyone who can read the table.

use aegis::aegis256::Aegis256;
use aes_gcm::aead::{self, Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm_siv::Aes256GcmSiv;
use aes_siv::siv::Aes256Siv;
use ascon_aead::AsconAead128;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ocb3::Ocb3;
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use pgrx::prelude::*;
use sha2::Sha256;
use std::cell::RefCell;
use std::ffi::CString;
use std::rc::Rc;

::pgrx::pg_module_magic!(name, version);

type HmacSha256 = Hmac<Sha256>;

const MIN_KEY_LEN: usize = 32;
const START: char = '\u{2}';
const END: char = '\u{3}';

/// Supported AEAD ciphers. The id is the first byte of every ciphertext, so
/// enc_decrypt can handle any mix. Ids are part of the storage format: never
/// renumber or reuse one.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Alg {
    Aes256Gcm = 1,
    Aes256GcmSiv = 2,
    ChaCha20Poly1305 = 3,
    XChaCha20Poly1305 = 4,
    Aegis256 = 5,
    AsconAead128 = 6,
    /// Deterministic: same plaintext + key -> same ciphertext (no nonce).
    Aes256Siv = 7,
    Aes256Ocb = 8,
}

const ALGS: [(Alg, &str); 8] = [
    (Alg::Aes256Gcm, "aes-256-gcm"),
    (Alg::Aes256GcmSiv, "aes-256-gcm-siv"),
    (Alg::ChaCha20Poly1305, "chacha20-poly1305"),
    (Alg::XChaCha20Poly1305, "xchacha20-poly1305"),
    (Alg::Aegis256, "aegis-256"),
    (Alg::AsconAead128, "ascon-aead128"),
    (Alg::Aes256Siv, "aes-256-siv"),
    (Alg::Aes256Ocb, "aes-256-ocb"),
];

/// Hash used for blind-index tokens. Every row of a table, and every query on
/// it, must use the same one: tokens from different hashes never match.
#[derive(Clone, Copy, PartialEq)]
enum TokenHash {
    HmacSha256,
    Blake3,
}

const TOKEN_HASHES: [(TokenHash, &str); 2] = [
    (TokenHash::HmacSha256, "hmac-sha256"),
    (TokenHash::Blake3, "blake3"),
];

impl Alg {
    fn name(self) -> &'static str {
        ALGS.iter().find(|(a, _)| *a == self).unwrap().1
    }

    fn from_name(name: &str) -> Alg {
        let lower = name.to_lowercase();
        ALGS.iter()
            .find(|(_, n)| *n == lower)
            .map(|(a, _)| *a)
            .unwrap_or_else(|| {
                let names: Vec<_> = ALGS.iter().map(|(_, n)| *n).collect();
                error!(
                    "encsearch: unknown algorithm '{name}' (supported: {})",
                    names.join(", ")
                )
            })
    }

    fn from_id(id: u8) -> Option<Alg> {
        ALGS.iter().map(|(a, _)| *a).find(|a| *a as u8 == id)
    }
}

static SESSION_KEY: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static DEFAULT_ALG: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(Some(c"aes-256-gcm"));
static TOKEN_HASH: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(Some(c"hmac-sha256"));

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    GucRegistry::define_string_guc(
        c"encsearch.key",
        c"Session key used when an encsearch function is called without a key.",
        c"Hidden from SHOW ALL and from non-superusers.",
        &SESSION_KEY,
        GucContext::Userset,
        GucFlags::NO_SHOW_ALL | GucFlags::SUPERUSER_ONLY,
    );
    GucRegistry::define_string_guc(
        c"encsearch.algorithm",
        c"Cipher used by enc_encrypt when no algorithm is given.",
        c"See enc_algorithms() for the list.",
        &DEFAULT_ALG,
        GucContext::Userset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        c"encsearch.token_hash",
        c"Hash for blind-index tokens: hmac-sha256 or blake3.",
        c"Must match the hash the table's tokens were built with.",
        &TOKEN_HASH,
        GucContext::Userset,
        GucFlags::default(),
    );
}

fn token_hash() -> TokenHash {
    let name = TOKEN_HASH
        .get()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| "hmac-sha256".into());
    TOKEN_HASHES
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(h, _)| *h)
        .unwrap_or_else(|| {
            error!("encsearch: unknown token_hash '{name}' (supported: hmac-sha256, blake3)")
        })
}

fn default_alg() -> Alg {
    match DEFAULT_ALG.get() {
        Some(a) => Alg::from_name(&a.to_string_lossy()),
        None => Alg::Aes256Gcm,
    }
}

fn session_key() -> String {
    match SESSION_KEY.get() {
        Some(k) if !k.as_bytes().is_empty() => k.to_string_lossy().into_owned(),
        _ => error!("encsearch: no key given and encsearch.key is not set"),
    }
}

struct Keys {
    aes_gcm: Aes256Gcm,
    aes_gcm_siv: Aes256GcmSiv,
    chacha: ChaCha20Poly1305,
    xchacha: XChaCha20Poly1305,
    aegis_key: [u8; 32],
    ascon: AsconAead128,
    // aes-siv's API needs `&mut self`, so it is built per call from this key.
    siv_key: [u8; 64],
    ocb: Ocb3<aes::Aes256>,
    hmac: TokenMac,
    blake3: TokenMac,
}

enum TokenMac {
    Hmac(HmacSha256),
    Blake3(Box<blake3::Hasher>),
}

impl Keys {
    fn mac(&self) -> &TokenMac {
        match token_hash() {
            TokenHash::HmacSha256 => &self.hmac,
            TokenHash::Blake3 => &self.blake3,
        }
    }
}

thread_local! {
    // Cache of the last key's derived state, so per-row calls skip HKDF and
    // the AES key schedule.
    static KEY_CACHE: RefCell<Option<(String, Rc<Keys>)>> = const { RefCell::new(None) };
}

fn keys(key: &str) -> Rc<Keys> {
    KEY_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((k, keys)) = cache.as_ref() {
            if k == key {
                return keys.clone();
            }
        }
        // Short keys could be brute-forced offline from the blind index.
        if key.chars().count() < MIN_KEY_LEN {
            error!("encsearch: key must be at least {MIN_KEY_LEN} characters (generate one with enc_gen_key())");
        }
        // Each cipher gets its own subkey; never reuse one key across algorithms.
        let hk = Hkdf::<Sha256>::new(Some(b"encsearch-v1"), key.as_bytes());
        let derive = |info: &[u8]| {
            let mut k = [0u8; 32];
            hk.expand(info, &mut k).expect("hkdf expand");
            k
        };
        let mut siv_key = [0u8; 64];
        hk.expand(b"encryption/aes-256-siv", &mut siv_key).expect("hkdf expand");
        let keys = Rc::new(Keys {
            // AES-256-GCM keeps the unsuffixed "encryption" label from the first format.
            aes_gcm: Aes256Gcm::new_from_slice(&derive(b"encryption")).expect("key"),
            aes_gcm_siv: Aes256GcmSiv::new_from_slice(&derive(b"encryption/aes-256-gcm-siv"))
                .expect("key"),
            chacha: ChaCha20Poly1305::new_from_slice(&derive(b"encryption/chacha20-poly1305"))
                .expect("key"),
            xchacha: XChaCha20Poly1305::new_from_slice(&derive(b"encryption/xchacha20-poly1305"))
                .expect("key"),
            aegis_key: derive(b"encryption/aegis-256"),
            // Ascon-AEAD128 takes a 128-bit key.
            ascon: AsconAead128::new_from_slice(&derive(b"encryption/ascon-aead128")[..16])
                .expect("key"),
            siv_key,
            ocb: Ocb3::new_from_slice(&derive(b"encryption/aes-256-ocb")).expect("key"),
            hmac: TokenMac::Hmac(
                <HmacSha256 as KeyInit>::new_from_slice(&derive(b"blind-index")).expect("key"),
            ),
            blake3: TokenMac::Blake3(Box::new(blake3::Hasher::new_keyed(&derive(b"blind-index/blake3")))),
        });
        *cache = Some((key.to_owned(), keys.clone()));
        keys
    })
}

fn token(mac: &TokenMac, tag: u8, data: &[u8]) -> i64 {
    let mut out = [0u8; 8];
    match mac {
        TokenMac::Hmac(h) => {
            let mut m = h.clone();
            m.update(&[tag]);
            m.update(data);
            out.copy_from_slice(&m.finalize().into_bytes()[..8]);
        }
        TokenMac::Blake3(h) => {
            let mut m = (**h).clone(); // clone the hasher, not the Box
            m.update(&[tag]);
            m.update(data);
            out.copy_from_slice(&m.finalize().as_bytes()[..8]);
        }
    }
    i64::from_le_bytes(out)
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
}

fn push_ngrams(mac: &TokenMac, chars: &[char], n: usize, out: &mut Vec<i64>) {
    let tag = if n == 3 { b't' } else { b'b' };
    let mut buf = String::with_capacity(4 * n);
    for w in chars.windows(n) {
        buf.clear();
        buf.extend(w);
        out.push(token(mac, tag, buf.as_bytes()));
    }
}

fn finish(mut v: Vec<i64>) -> Vec<i64> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Random 256-bit key as 64 hex characters.
#[pg_extern(volatile, parallel_safe)]
fn enc_gen_key() -> String {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("getrandom");
    k.iter().map(|b| format!("{b:02x}")).collect()
}

/// Output: algorithm id || random nonce || ciphertext+tag.
fn seal<C: Aead>(cipher: &C, alg: Alg, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = aead::Nonce::<C>::default();
    getrandom::fill(&mut nonce).expect("getrandom");
    let ct = cipher.encrypt(&nonce, plaintext).expect("encrypt");
    let mut out = Vec::with_capacity(1 + nonce.len() + ct.len());
    out.push(alg as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// `data` is everything after the algorithm id byte.
fn open<C: Aead>(cipher: &C, data: &[u8]) -> Option<Vec<u8>> {
    let nonce_len = aead::Nonce::<C>::default().len();
    if data.len() < nonce_len {
        return None;
    }
    let (nonce, ct) = data.split_at(nonce_len);
    cipher
        .decrypt(&aead::Nonce::<C>::try_from(nonce).ok()?, ct)
        .ok()
}

fn encrypt_with(plaintext: &str, key: &str, alg: Alg) -> Vec<u8> {
    let k = keys(key);
    let pt = plaintext.as_bytes();
    match alg {
        Alg::Aes256Gcm => seal(&k.aes_gcm, alg, pt),
        Alg::Aes256GcmSiv => seal(&k.aes_gcm_siv, alg, pt),
        Alg::ChaCha20Poly1305 => seal(&k.chacha, alg, pt),
        Alg::XChaCha20Poly1305 => seal(&k.xchacha, alg, pt),
        Alg::AsconAead128 => seal(&k.ascon, alg, pt),
        Alg::Aes256Ocb => seal(&k.ocb, alg, pt),
        Alg::Aegis256 => {
            // id || 32-byte nonce || ciphertext || 16-byte tag
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).expect("getrandom");
            let (ct, tag) = Aegis256::<16>::new(&k.aegis_key, &nonce).encrypt(pt, &[]);
            let mut out = Vec::with_capacity(1 + 32 + ct.len() + 16);
            out.push(alg as u8);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            out.extend_from_slice(&tag);
            out
        }
        Alg::Aes256Siv => {
            // id || synthetic IV (16) || ciphertext. No nonce, so deterministic.
            let mut siv = Aes256Siv::new_from_slice(&k.siv_key).expect("key");
            let ct = siv
                .encrypt(std::iter::empty::<&[u8]>(), pt)
                .expect("encrypt");
            let mut out = Vec::with_capacity(1 + ct.len());
            out.push(alg as u8);
            out.extend_from_slice(&ct);
            out
        }
    }
}

fn open_aegis(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 + 16 {
        return None;
    }
    let (nonce, rest) = data.split_at(32);
    let (ct, tag) = rest.split_at(rest.len() - 16);
    Aegis256::<16>::new(key, nonce.try_into().ok()?)
        .decrypt(ct, tag.try_into().ok()?, &[])
        .ok()
}

/// Encrypt with the session's default algorithm (encsearch.algorithm).
#[pg_extern(strict, volatile, parallel_safe)]
fn enc_encrypt(plaintext: &str, key: &str) -> Vec<u8> {
    encrypt_with(plaintext, key, default_alg())
}

/// Encrypt with a named algorithm, e.g. 'xchacha20-poly1305'.
#[pg_extern(strict, volatile, parallel_safe, name = "enc_encrypt")]
fn enc_encrypt_alg(plaintext: &str, key: &str, algorithm: &str) -> Vec<u8> {
    encrypt_with(plaintext, key, Alg::from_name(algorithm))
}

/// Which algorithm encrypted this value.
#[pg_extern(strict, immutable, parallel_safe)]
fn enc_algorithm(ciphertext: &[u8]) -> &'static str {
    match ciphertext.first().and_then(|id| Alg::from_id(*id)) {
        Some(alg) => alg.name(),
        None => error!("encsearch: invalid ciphertext"),
    }
}

/// Names of all supported algorithms.
#[pg_extern(immutable, parallel_safe)]
fn enc_algorithms() -> Vec<&'static str> {
    ALGS.iter().map(|(_, n)| *n).collect()
}

#[pg_extern(strict, immutable, parallel_safe)]
fn enc_decrypt(ciphertext: &[u8], key: &str) -> String {
    let Some(alg) = ciphertext.first().and_then(|id| Alg::from_id(*id)) else {
        error!("encsearch: invalid ciphertext");
    };
    let k = keys(key);
    let data = &ciphertext[1..];
    let pt = match alg {
        Alg::Aes256Gcm => open(&k.aes_gcm, data),
        Alg::Aes256GcmSiv => open(&k.aes_gcm_siv, data),
        Alg::ChaCha20Poly1305 => open(&k.chacha, data),
        Alg::XChaCha20Poly1305 => open(&k.xchacha, data),
        Alg::AsconAead128 => open(&k.ascon, data),
        Alg::Aes256Ocb => open(&k.ocb, data),
        Alg::Aegis256 => open_aegis(&k.aegis_key, data),
        Alg::Aes256Siv => Aes256Siv::new_from_slice(&k.siv_key)
            .expect("key")
            .decrypt(std::iter::empty::<&[u8]>(), data)
            .ok(),
    }
    .unwrap_or_else(|| error!("encsearch: decryption failed (wrong key or corrupted data)"));
    String::from_utf8(pt).unwrap_or_else(|_| error!("encsearch: plaintext is not valid UTF-8"))
}

/// All blind-index tokens for a value. Store in an int8[] column with a GIN index.
#[pg_extern(strict, stable, parallel_safe)]
fn enc_index(plaintext: &str, key: &str) -> Vec<i64> {
    let k = keys(key);
    let mac = k.mac();
    let lower = plaintext.to_lowercase();
    let mut out = Vec::new();
    out.push(token(mac, b'x', lower.as_bytes()));
    for w in words(&lower) {
        out.push(token(mac, b'w', w.as_bytes()));
    }
    let chars: Vec<char> = std::iter::once(START)
        .chain(lower.chars())
        .chain(std::iter::once(END))
        .collect();
    push_ngrams(mac, &chars, 3, &mut out);
    push_ngrams(mac, &chars, 2, &mut out);
    finish(out)
}

/// Tokens for a case-insensitive exact match. Use: idx @> enc_q_exact('v', key)
#[pg_extern(strict, stable, parallel_safe)]
fn enc_q_exact(value: &str, key: &str) -> Vec<i64> {
    let k = keys(key);
    let mac = k.mac();
    vec![token(mac, b'x', value.to_lowercase().as_bytes())]
}

/// Tokens requiring every word in `query` to be present.
#[pg_extern(strict, stable, parallel_safe)]
fn enc_q_words(query: &str, key: &str) -> Vec<i64> {
    let k = keys(key);
    let mac = k.mac();
    let lower = query.to_lowercase();
    finish(
        words(&lower)
            .map(|w| token(mac, b'w', w.as_bytes()))
            .collect(),
    )
}

/// Tokens for a LIKE pattern ('abc%', '%abc', '%abc%', 'a_c%' ...).
/// Literal runs (counting start/end anchors) of >= 3 chars become trigram
/// tokens, runs of 2 chars become bigram tokens. A pattern with no such run
/// (e.g. '%a%') returns '{}', which matches every row, so the recheck does all
/// the work (slow path).
#[pg_extern(strict, stable, parallel_safe)]
fn enc_q_like(pattern: &str, key: &str) -> Vec<i64> {
    let k = keys(key);
    let mac = k.mac();
    let lower = pattern.to_lowercase();

    // Split the pattern into literal segments, handling '\' escapes.
    let mut segments: Vec<Vec<char>> = vec![vec![START]];
    let mut it = lower.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                if let Some(n) = it.next() {
                    segments.last_mut().unwrap().push(n);
                }
            }
            '%' | '_' => segments.push(Vec::new()),
            _ => segments.last_mut().unwrap().push(c),
        }
    }
    // Anchor the end only if the pattern didn't end in a wildcard.
    segments.last_mut().unwrap().push(END);

    let mut out = Vec::new();
    for seg in &segments {
        match seg.len() {
            0 | 1 => {}
            2 => push_ngrams(mac, seg, 2, &mut out),
            _ => push_ngrams(mac, seg, 3, &mut out),
        }
    }
    finish(out)
}

// Overloads that read the key from `SET encsearch.key`. STABLE, not IMMUTABLE,
// because the result depends on a session setting.

#[pg_extern(strict, volatile, parallel_safe, name = "enc_encrypt")]
fn enc_encrypt_s(plaintext: &str) -> Vec<u8> {
    enc_encrypt(plaintext, &session_key())
}

#[pg_extern(strict, stable, parallel_safe, name = "enc_decrypt")]
fn enc_decrypt_s(ciphertext: &[u8]) -> String {
    enc_decrypt(ciphertext, &session_key())
}

#[pg_extern(strict, stable, parallel_safe, name = "enc_index")]
fn enc_index_s(plaintext: &str) -> Vec<i64> {
    enc_index(plaintext, &session_key())
}

#[pg_extern(strict, stable, parallel_safe, name = "enc_q_exact")]
fn enc_q_exact_s(value: &str) -> Vec<i64> {
    enc_q_exact(value, &session_key())
}

#[pg_extern(strict, stable, parallel_safe, name = "enc_q_words")]
fn enc_q_words_s(query: &str) -> Vec<i64> {
    enc_q_words(query, &session_key())
}

#[pg_extern(strict, stable, parallel_safe, name = "enc_q_like")]
fn enc_q_like_s(pattern: &str) -> Vec<i64> {
    enc_q_like(pattern, &session_key())
}

// One-call search helpers. Plain SQL functions so the planner inlines them and
// the `idx @> ...` part can use the GIN index.
extension_sql!(
    r#"
CREATE FUNCTION enc_like(body bytea, idx int8[], pattern text, key text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_like(pattern, key) AND enc_decrypt(body, key) LIKE pattern $$;
CREATE FUNCTION enc_like(body bytea, idx int8[], pattern text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_like(pattern) AND enc_decrypt(body) LIKE pattern $$;

CREATE FUNCTION enc_ilike(body bytea, idx int8[], pattern text, key text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_like(pattern, key) AND enc_decrypt(body, key) ILIKE pattern $$;
CREATE FUNCTION enc_ilike(body bytea, idx int8[], pattern text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_like(pattern) AND enc_decrypt(body) ILIKE pattern $$;

CREATE FUNCTION enc_eq(body bytea, idx int8[], value text, key text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_exact(value, key) AND enc_decrypt(body, key) = value $$;
CREATE FUNCTION enc_eq(body bytea, idx int8[], value text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_exact(value) AND enc_decrypt(body) = value $$;

CREATE FUNCTION enc_has_words(idx int8[], query text, key text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_words(query, key) $$;
CREATE FUNCTION enc_has_words(idx int8[], query text) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT idx @> enc_q_words(query) $$;
"#,
    name = "search_helpers",
    requires = [
        enc_decrypt,
        enc_decrypt_s,
        enc_q_like,
        enc_q_like_s,
        enc_q_exact,
        enc_q_exact_s,
        enc_q_words,
        enc_q_words_s
    ],
);

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    const K: &str = "test-key-0123456789abcdef0123456789";
    const K2: &str = "other-key-0123456789abcdef012345678";

    #[pg_test]
    fn roundtrip() {
        let ct = crate::enc_encrypt("Hello Wörld", K);
        assert_eq!(crate::enc_decrypt(&ct, K), "Hello Wörld");
        assert_ne!(crate::enc_encrypt("x", K), crate::enc_encrypt("x", K));
    }

    #[pg_test]
    #[should_panic(expected = "decryption failed")]
    fn wrong_key() {
        let ct = crate::enc_encrypt("secret", K);
        crate::enc_decrypt(&ct, K2);
    }

    #[pg_test]
    fn all_algorithms() {
        for name in crate::enc_algorithms() {
            let ct = crate::enc_encrypt_alg("Hello Wörld", K, name);
            assert_eq!(crate::enc_algorithm(&ct), name);
            assert_eq!(crate::enc_decrypt(&ct, K), "Hello Wörld");
            // Each algorithm uses its own subkey, so ciphertexts never decrypt
            // under another algorithm's id.
            let mut forged = ct.clone();
            forged[0] = if forged[0] == 1 { 2 } else { 1 };
            assert!(std::panic::catch_unwind(|| crate::enc_decrypt(&forged, K)).is_err());
        }
        // XChaCha uses a 24-byte nonce, the others 12.
        let x = crate::enc_encrypt_alg("", K, "xchacha20-poly1305");
        let a = crate::enc_encrypt_alg("", K, "aes-256-gcm");
        assert_eq!(x.len(), 1 + 24 + 16);
        assert_eq!(a.len(), 1 + 12 + 16);
    }

    #[pg_test]
    fn siv_is_deterministic_others_are_not() {
        for name in crate::enc_algorithms() {
            let a = crate::enc_encrypt_alg("same text", K, name);
            let b = crate::enc_encrypt_alg("same text", K, name);
            assert_eq!(a == b, name == "aes-256-siv", "{name}");
        }
        // Still key-dependent.
        assert_ne!(
            crate::enc_encrypt_alg("same text", K, "aes-256-siv"),
            crate::enc_encrypt_alg("same text", K2, "aes-256-siv")
        );
    }

    #[pg_test]
    fn blake3_tokens() {
        let hmac_idx = crate::enc_index("Patient has diabetes", K);
        Spi::run("SET encsearch.token_hash = 'blake3'").unwrap();
        let idx = crate::enc_index("Patient has diabetes", K);
        assert_eq!(idx.len(), hmac_idx.len());
        assert!(!contains(&idx, &hmac_idx[..1]));
        assert!(contains(&idx, &crate::enc_q_words("diabetes", K)));
        assert!(contains(&idx, &crate::enc_q_like("%iabet%", K)));
        assert!(!contains(&idx, &crate::enc_q_words("cancer", K)));
    }

    #[pg_test]
    #[should_panic(expected = "unknown token_hash")]
    fn unknown_token_hash() {
        Spi::run("SET encsearch.token_hash = 'md5'").unwrap();
        crate::enc_index("x", K);
    }

    #[pg_test]
    fn tamper_detected() {
        for name in crate::enc_algorithms() {
            let mut ct = crate::enc_encrypt_alg("secret", K, name);
            let last = ct.len() - 1;
            ct[last] ^= 1;
            assert!(
                std::panic::catch_unwind(|| crate::enc_decrypt(&ct, K)).is_err(),
                "{name}"
            );
        }
    }

    #[pg_test]
    fn default_algorithm_setting() {
        Spi::run("SET encsearch.algorithm = 'chacha20-poly1305'").unwrap();
        let alg = Spi::get_one::<String>(&format!("SELECT enc_algorithm(enc_encrypt('x', '{K}'))"));
        assert_eq!(alg, Ok(Some("chacha20-poly1305".into())));
    }

    #[pg_test]
    #[should_panic(expected = "unknown algorithm")]
    fn unknown_algorithm() {
        crate::enc_encrypt_alg("x", K, "rot13");
    }

    #[pg_test]
    #[should_panic(expected = "at least 32 characters")]
    fn short_key_rejected() {
        crate::enc_encrypt("secret", "my-key");
    }

    #[pg_test]
    fn gen_key() {
        let k = crate::enc_gen_key();
        assert_eq!(k.len(), 64);
        assert_ne!(k, crate::enc_gen_key());
    }

    fn contains(idx: &[i64], q: &[i64]) -> bool {
        q.iter().all(|t| idx.binary_search(t).is_ok())
    }

    #[pg_test]
    fn search_kinds() {
        let idx = crate::enc_index("Patient has Diabetes type-2", K);
        assert!(contains(
            &idx,
            &crate::enc_q_exact("patient has diabetes TYPE-2", K)
        ));
        assert!(!contains(
            &idx,
            &crate::enc_q_exact("patient has diabetes", K)
        ));
        assert!(contains(&idx, &crate::enc_q_words("diabetes patient", K)));
        assert!(!contains(&idx, &crate::enc_q_words("cancer", K)));
        assert!(contains(&idx, &crate::enc_q_like("pati%", K)));
        assert!(!contains(&idx, &crate::enc_q_like("diab%", K)));
        assert!(contains(&idx, &crate::enc_q_like("%type-2", K)));
        assert!(contains(&idx, &crate::enc_q_like("%iabet%", K)));
        assert!(!contains(&idx, &crate::enc_q_like("%xyz%", K)));
        // Different key -> different tokens.
        assert!(!contains(&idx, &crate::enc_q_words("diabetes", K2)));
    }

    #[pg_test]
    fn short_patterns_use_bigrams() {
        let idx = crate::enc_index("Patient", K);
        assert!(!crate::enc_q_like("%ti%", K).is_empty());
        assert!(contains(&idx, &crate::enc_q_like("%ti%", K)));
        assert!(!contains(&idx, &crate::enc_q_like("%zz%", K)));
        assert!(contains(&idx, &crate::enc_q_like("p%", K)));
        assert!(!contains(&idx, &crate::enc_q_like("a%", K)));
        assert!(crate::enc_q_like("%a%", K).is_empty());
    }

    #[pg_test]
    fn sql_end_to_end() {
        Spi::run(&format!(
            "CREATE TABLE notes(id serial, body bytea, idx int8[]);
             CREATE INDEX ON notes USING gin(idx);
             INSERT INTO notes(body, idx)
               SELECT enc_encrypt(t, '{K}'), enc_index(t, '{K}')
               FROM unnest(ARRAY['alpha beta', 'gamma delta', 'Alphabet soup']) t;"
        ))
        .unwrap();
        let count = |q: &str| Spi::get_one::<i64>(&format!("SELECT count(*) FROM notes WHERE {q}"));
        assert_eq!(
            count(&format!("enc_like(body, idx, '%alpha%', '{K}')")),
            Ok(Some(1))
        );
        assert_eq!(
            count(&format!("enc_ilike(body, idx, '%alpha%', '{K}')")),
            Ok(Some(2))
        );
        assert_eq!(
            count(&format!("enc_eq(body, idx, 'gamma delta', '{K}')")),
            Ok(Some(1))
        );
        assert_eq!(
            count(&format!("enc_has_words(idx, 'soup', '{K}')")),
            Ok(Some(1))
        );

        // Session key instead of a key argument.
        Spi::run(&format!("SET encsearch.key = '{K}'")).unwrap();
        assert_eq!(count("enc_ilike(body, idx, '%alpha%')"), Ok(Some(2)));
        assert_eq!(count("enc_has_words(idx, 'beta')"), Ok(Some(1)));
        let pt = Spi::get_one::<String>("SELECT enc_decrypt(enc_encrypt('hi'))");
        assert_eq!(pt, Ok(Some("hi".into())));
    }

    #[pg_test]
    #[should_panic(expected = "encsearch.key is not set")]
    fn missing_session_key() {
        Spi::run("SELECT enc_encrypt('hi')").unwrap();
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
