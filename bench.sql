-- encsearch benchmark: 1M encrypted rows, compare index search vs decrypt-and-scan.
-- Run: cargo pgrx run pg17 --release, then \i bench.sql
\timing on
CREATE EXTENSION IF NOT EXISTS encsearch;
DROP TABLE IF EXISTS notes;
CREATE TABLE notes(id bigserial PRIMARY KEY, body bytea NOT NULL, idx int8[] NOT NULL);

-- Synthetic text: random words from a small vocabulary plus a unique code.
INSERT INTO notes(body, idx)
SELECT enc_encrypt(t, 'bench-key-0123456789abcdef0123456789'), enc_index(t, 'bench-key-0123456789abcdef0123456789')
FROM (
  SELECT (ARRAY['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet'])[1 + (random()*9)::int]
         || ' ' || (ARRAY['red','green','blue','cyan','magenta','yellow','black','white'])[1 + (random()*7)::int]
         || ' order-' || g AS t
  FROM generate_series(1, 1000000) g
) s;

CREATE INDEX notes_idx_gin ON notes USING gin(idx);
VACUUM ANALYZE notes;
SELECT pg_size_pretty(pg_total_relation_size('notes')) AS table_size,
       pg_size_pretty(pg_relation_size('notes_idx_gin')) AS index_size;

-- 1. Exact match (case-insensitive index, exact recheck)
SELECT id FROM notes
WHERE idx @> enc_q_exact('echo blue order-424242', 'bench-key-0123456789abcdef0123456789')
  AND enc_decrypt(body, 'bench-key-0123456789abcdef0123456789') = 'echo blue order-424242';

-- 2. Word search
SELECT count(*) FROM notes
WHERE idx @> enc_q_words('order-777777', 'bench-key-0123456789abcdef0123456789');

-- 3. Prefix
SELECT count(*) FROM notes
WHERE idx @> enc_q_like('golf green order-12345%', 'bench-key-0123456789abcdef0123456789')
  AND enc_decrypt(body, 'bench-key-0123456789abcdef0123456789') LIKE 'golf green order-12345%';

-- 4. Substring
SELECT count(*) FROM notes
WHERE idx @> enc_q_like('%der-99999%', 'bench-key-0123456789abcdef0123456789')
  AND enc_decrypt(body, 'bench-key-0123456789abcdef0123456789') LIKE '%der-99999%';

-- 5. Decrypt-and-scan (regex, no index) -- the slow baseline
SELECT count(*) FROM notes
WHERE enc_decrypt(body, 'bench-key-0123456789abcdef0123456789') ~ 'order-9999[0-9]$';

EXPLAIN (ANALYZE, COSTS OFF)
SELECT count(*) FROM notes
WHERE idx @> enc_q_like('%der-99999%', 'bench-key-0123456789abcdef0123456789')
  AND enc_decrypt(body, 'bench-key-0123456789abcdef0123456789') LIKE '%der-99999%';

-- 6. Short pattern (bigram tokens): previously a full decrypt scan
SELECT count(*) FROM notes
WHERE enc_like(body, idx, 'golf b%', 'bench-key-0123456789abcdef0123456789');

-- 7. One-call helpers with the session key -- must still use the GIN index
SET encsearch.key = 'bench-key-0123456789abcdef0123456789';
SELECT count(*) FROM notes WHERE enc_like(body, idx, '%der-99999%');
SELECT id FROM notes WHERE enc_eq(body, idx, 'golf green order-424242');
EXPLAIN (COSTS OFF) SELECT count(*) FROM notes WHERE enc_like(body, idx, '%der-99999%');
