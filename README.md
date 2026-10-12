# encsearch

Searchable encryption for PostgreSQL. Text is encrypted with an AEAD cipher
(AES-256-GCM by default) and stored next to a keyed **blind index**: HMAC-SHA256
tokens of the value, its words and its 2- and 3-character chunks, in a
GIN-indexed `int8[]` column. That lets you run exact, word, prefix, suffix and
substring searches without decrypting the table.

On 1M rows, a substring search takes about 25 ms, versus about 3.9 s to decrypt
and scan every row.

> **Status: v0.1.1, early release.** Read [Security notes](#security-notes)
> before storing real data. The blind index trades some privacy for speed.

## Install

Requirements: PostgreSQL 17 (other versions untested), Rust, a C compiler, and
[cargo-pgrx](https://github.com/pgcentralfoundation/pgrx) 0.19.3.

```sh
cargo install cargo-pgrx --version 0.19.3 --locked
cargo pgrx init --pg17 $(which pg_config)

git clone https://github.com/lokeshmulpuru/encsearch.git
cd encsearch
make install            # or: cargo pgrx install --release --pg-config $(which pg_config)
```

From [PGXN](https://pgxn.org/dist/encsearch/) (still needs Rust and cargo-pgrx):

```sh
pgxn install encsearch
```

## Setup

```sql
-- postgresql.conf (needed so the session key stays hidden from other roles)
session_preload_libraries = 'encsearch'

CREATE EXTENSION encsearch;
SELECT enc_gen_key();                      -- random 64-char key; keys must be >= 32 chars

CREATE TABLE notes(id bigserial PRIMARY KEY, body bytea, idx int8[]);
CREATE INDEX ON notes USING gin(idx);
```

## Usage

Set the key once per session, or pass it as the last argument to any function.

```sql
SET encsearch.key = '<your key>';

INSERT INTO notes(body, idx) VALUES (enc_encrypt('Patient has diabetes'), enc_index('Patient has diabetes'));

SELECT enc_decrypt(body) FROM notes WHERE enc_like(body, idx, '%diab%');      -- LIKE
SELECT enc_decrypt(body) FROM notes WHERE enc_ilike(body, idx, 'patient%');   -- ILIKE
SELECT enc_decrypt(body) FROM notes WHERE enc_eq(body, idx, 'Patient has diabetes');
SELECT enc_decrypt(body) FROM notes WHERE enc_has_words(idx, 'diabetes patient');
SELECT enc_decrypt(body) FROM notes WHERE enc_decrypt(body) ~ 'regex';        -- slow full scan
```

| Function | Purpose |
|---|---|
| `enc_encrypt(text [, key])` / `enc_decrypt(bytea [, key])` | encrypt (default cipher) / decrypt (any cipher) |
| `enc_index(text [, key])` | blind-index tokens to store in `idx` |
| `enc_like` / `enc_ilike` / `enc_eq` / `enc_has_words` | one-call searches that use the GIN index |
| `enc_q_like` / `enc_q_exact` / `enc_q_words` | raw query tokens, for `idx @> ...` |
| `enc_gen_key()` | random key |
| `enc_encrypt(text, key, algorithm)` | encrypt with a specific cipher |
| `enc_algorithm(bytea)` / `enc_algorithms()` | which cipher encrypted a value / list all |

## Ciphers

| Name | Notes |
|---|---|
| `aes-256-gcm` (default) | Standard choice; hardware-accelerated |
| `aes-256-gcm-siv` | Safe even if a nonce ever repeats |
| `aes-256-ocb` | Single-pass AES mode |
| `aes-256-siv` | **Deterministic**: same text -> same ciphertext (reveals duplicates) |
| `aegis-256` | Newest and fastest on AES hardware (IETF draft) |
| `chacha20-poly1305` | Fast on CPUs without AES hardware |
| `xchacha20-poly1305` | 24-byte nonce: random nonces safe at any scale |
| `ascon-aead128` | NIST lightweight standard (SP 800-232); 128-bit key |

Pick one per call (`enc_encrypt(text, key, 'aegis-256')`) or set a default with
`SET encsearch.algorithm = '...'`. The first byte of each ciphertext records
the cipher, so `enc_decrypt` handles mixed data and switching needs no
migration. Each cipher uses its own subkey derived from your key.

Encrypt+decrypt inside Postgres (Apple Silicon, release build):

| Cipher | 1M x 100 B | 100k x 4 KB | Bytes added |
|---|---|---|---|
| aegis-256 | 1.40 s | 1.07 s | 49 |
| aes-256-gcm | 1.40 s | 1.20 s | 29 |
| aes-256-gcm-siv | 1.78 s | 1.24 s | 29 |
| aes-256-ocb | 1.45 s | 1.28 s | 29 |
| aes-256-siv | 1.47 s | 1.80 s | 17 |
| chacha20-poly1305 | 2.41 s | 2.08 s | 29 |
| xchacha20-poly1305 | 2.58 s | 2.09 s | 41 |
| ascon-aead128 | 1.90 s | 2.66 s | 33 |

## Token hash

`SET encsearch.token_hash = 'hmac-sha256'` (default) or `'blake3'`. Tokens from
different hashes never match, so build and query a table with the same one.
On Apple Silicon HMAC-SHA256 is faster for these tiny inputs (SHA-256 has
hardware instructions): 1M rows of `enc_index` took 6.7 s vs 10.2 s for BLAKE3.

## Performance (1M rows, Apple Silicon, PG17)

Exact ~3 ms · word ~2 ms · substring ~25 ms · prefix ~53 ms · full decrypt scan ~3.9 s.
Table 725 MB, GIN index 159 MB.

## Security notes

- The blind index leaks to anyone who can read the table: which rows share a
  value, a word, or 2-3 character chunks, and how often. This is inherent to
  indexed search over encrypted data; it cannot be removed without losing speed.
- The key reaches the server, so it can appear in server logs when
  `log_statement` is on (including bind parameters, unless
  `log_parameter_max_length = 0`). Prefer setting the session key once per
  connection, and keep statement logging off for these sessions.
- Without `session_preload_libraries`, a key `SET` before the library loads is
  stored as an ordinary placeholder setting and is visible via `SHOW`.

## Development

```sh
cargo pgrx test pg17     # run the test suite inside a temporary Postgres
cargo pgrx run pg17      # psql with the extension installed
psql -f bench.sql        # 1M-row benchmark
```

## License

[PostgreSQL License](LICENSE).
