# sct-check

Is this certificate really in Certificate Transparency? `sct-check` reads the SCTs embedded in a
host's certificate, or in a chain file, and checks two things for each:

- the log's signature on the SCT, with the log's key from Chrome's log list;
- that the log really holds the certificate, with an inclusion proof that leads to the log's
  own signed tree head.

Then it checks the SCTs against Chrome's CT policy: enough logs, from enough operators, for the
certificate's lifetime.

It works with both kinds of log Chrome trusts: RFC 6962 logs and the newer
[static-ct-api](https://c2sp.org/static-ct-api) (tiled) logs. It exits 1 when an SCT fails, so it
fits a cron job or a monitoring check.

## Why

An SCT is a log's promise to publish a certificate. Browsers check the signature on that
promise when they connect, but not whether the log kept it. Checking that is the auditor's job
in CT, and it's the part a log could quietly get wrong.

Most logs are now tiled. On 2026-11-13, Chrome's log list had 63 static-ct-api logs from 9
operators, against 26 RFC 6962 logs from 5. Let's Encrypt, Geomys, IPng Networks, Microsec,
GoDaddy and HARICA run only tiled logs. A tiled log has no `get-proof-by-hash`: it publishes a
signed checkpoint and the tree as static tiles, and the client builds the proof itself.
`sct-check` does that, using the `leaf_index` each static-ct-api SCT carries.

## Quick start

Needs Node 24 or later, and nothing else.

```sh
git clone https://github.com/Urthella/sct-check && cd sct-check
node src/main.ts letsencrypt.org www.google.com en.wikipedia.org
```

```text
letsencrypt.org  letsencrypt.org, issued by Let's Encrypt YE2, expires 2027-02-01 13:44 UTC
  ok    Cloudflare Nimbus2027 (rfc6962), SCT of 2026-11-03 14:43 UTC: entry 808627969 is in the log's tree of 1035466376 entries, signed 2026-11-13 21:39 UTC
  ok    DigiCert Sphinx2027h1 (rfc6962), SCT of 2026-11-03 14:43 UTC: entry 343493494 is in the log's tree of 476490816 entries, signed 2026-11-13 22:21 UTC
  ok    Chrome's CT policy: SCTs from 2 logs and 2 operators, and a certificate of 90 days needs 2 logs and 2 operators

www.google.com  www.google.com, issued by Google Trust Services WE2, expires 2027-01-26 08:29 UTC
  ok    DigiCert Wyvern2027h1 (rfc6962), SCT of 2026-11-03 09:29 UTC: entry 386413686 is in the log's tree of 533401984 entries, signed 2026-11-13 22:21 UTC
  ok    Let's Encrypt Willow2027h1 (static-ct-api), SCT of 2026-11-03 09:29 UTC: entry 910883989 is in the log's tree of 1145812385 entries, signed 2026-11-13 22:21 UTC
  ok    Chrome's CT policy: SCTs from 2 logs and 2 operators, and a certificate of 84 days needs 2 logs and 2 operators

en.wikipedia.org  *.wikipedia.org, issued by Let's Encrypt YE2, expires 2027-01-02 18:34 UTC
  ok    Sectigo Tiger2027h1 (rfc6962), SCT of 2026-10-04 19:33 UTC: entry 307544256 is in the log's tree of 887793890 entries, signed 2026-11-13 22:20 UTC
  ok    IPng Networks Gouda2027h1 (static-ct-api), SCT of 2026-10-04 19:33 UTC: entry 88798019 is in the log's tree of 410497260 entries, signed 2026-11-13 22:21 UTC
  ok    Chrome's CT policy: SCTs from 2 logs and 2 operators, and a certificate of 90 days needs 2 logs and 2 operators
```

Hosts can carry a port, as `host:443` or `[::1]:8443`. `--file PATH` checks a PEM chain file
instead, such as `fullchain.pem`: the first certificate is checked, and the second must be its
issuer, because every SCT covers the issuer's key. Repeat the flag for more files.

`--json` prints the results as JSON. `--log-list URL` uses another v3 log list instead of
Chrome's.

Some logs rate-limit anonymous clients. Geomys' logs ask for an email address in the
User-Agent; `--contact EMAIL` adds one. Without it, a rate-limited SCT is reported as an error
with the log's own message, after two retries.

The results and the exit code:

| Result | Meaning | Exit |
|---|---|---|
| `ok` | The log signed the SCT and proved the entry is in its tree. On the policy line: the policy is met. | 0 |
| `wait` | Signed, but not in the tree yet, and the log's maximum merge delay hasn't passed. | 0 |
| `FAIL` | A bad signature, a log that isn't in the list, an entry missing past the merge delay, a proof that doesn't match, or a badly signed tree head. On the policy line: the policy isn't met, which includes a certificate with no SCTs. | 1 |
| `ERROR` | A log couldn't be reached or read. | 2 |

## What it does

1. **Reads the certificate and its issuer**, from the TLS handshake or the chain file.
2. **Rebuilds the precertificate.** An SCT covers the precertificate's TBSCertificate, which is
   the certificate's own with the SCT list extension taken out. A small DER reader removes it and
   re-encodes the lengths, and nothing else changes.
3. **Checks each SCT's signature** over RFC 6962's `CertificateTimestamp`: the timestamp, the
   SHA-256 of the issuer's public key, the TBSCertificate and the SCT's extensions.
4. **Gets the log's signed tree head** and checks its signature. For an RFC 6962 log that's
   `get-sth`. For a static-ct-api log it's the checkpoint, a signed note whose log signature is
   picked by its key ID; other signatures, such as witnesses' and grease, are skipped.
5. **Proves inclusion.** The leaf hash is computed from the SCT. An RFC 6962 log is asked for a
   proof by that hash. For a tiled log, the proof is built from the tiles: each tile holds 256
   subtree hashes, 8 tree levels at a time, and partial tiles cover the right edge of the tree.
   Either way, the proof is checked against the signed root as in RFC 9162 section 2.1.3.2.
6. **Applies Chrome's CT policy** for embedded SCTs, as
   [published](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) on
   2026-11-14, to the SCTs whose signatures verify:
   - at least one SCT from a log that's qualified, usable or read-only;
   - SCTs from at least 2 distinct logs for a lifetime of up to 180 days, and 3 beyond that.
     Logs that are qualified, usable, read-only or retired count, but a retired log only counts
     if the earliest SCT predates its retirement;
   - among those, at least 2 operators, each SCT counting for the operator that ran its log
     when it was issued, from the list's `previous_operators`.

   Inclusion isn't part of the policy, so a policy that's met can still sit next to a failed
   SCT.

## How it's checked

- **Real certificates and real logs.** The fixtures were saved from live hosts and logs by
  [`scripts/fetch-fixtures.ts`](scripts/fetch-fixtures.ts):
  - every SCT in four real certificates verifies under its log's real key, which shows the
    precertificate is rebuilt exactly;
  - the leaf hash computed for a real Let's Encrypt Willow entry is the hash the log stores in
    its level 0 tile;
  - a real Willow checkpoint verifies, with its grease signature skipped;
  - a real Cloudflare Nimbus tree head and inclusion proof verify;
  - all four certificates meet Chrome's policy under the saved log list.
- **The policy, rule by rule**, in [`test/policy.test.ts`](test/policy.test.ts): exactly 180
  days against just over, two SCTs from one log, one operator, retired logs before and after
  the earliest SCT, no current log, pending and rejected logs, and a log that changed operators.
- **Proofs from tiles against a plain Merkle tree.** A tree written straight from RFC 6962, in
  [`test/tree.ts`](test/tree.ts), provides the tiles. The tool's proof must equal RFC 6962's audit
  path for every entry of trees of 1 to 70 entries, and for chosen entries of trees up to the
  spec's example of 70,000, across full and partial tiles. It must also ask only for tiles that
  exist, at their exact width.
- **End to end.** The CLI runs against a fake log of each kind. A test CA issues certificates
  with SCTs built by hand from RFC 6962's structures, not with the tool's own code:
  - SCTs that are signed and included pass, from a file and from a TLS server, and meet the
    policy;
  - two good SCTs from one log fail the policy, and a forged SCT doesn't count toward it;
  - each failure gives 1: a bad signature, an unknown log, an entry missing past the merge
    delay, an entry the tree doesn't hold, a missing `leaf_index`, a badly signed checkpoint or
    tree head, and no SCTs at all;
  - an entry within the merge delay waits;
  - a 429 is retried with the `--contact` in the User-Agent;
  - an unreadable log, steady rate limiting, an unreachable log list, a chain without its
    issuer and a self-signed certificate give 2.
- **Mutation testing.** Fifty-one deliberate bugs were planted one at a time, and the tests
  caught every one.
- **Live**, with `npm run crosscheck`. On 2026-11-14, twelve hosts had 30 SCTs between them. 29
  verified and were proven included: 24 in RFC 6962 logs from Google, Cloudflare, DigiCert,
  Sectigo and TrustAsia, and 5 in static-ct-api logs from Let's Encrypt and IPng Networks. The
  last one was in a Geomys log, which rate-limited the anonymous client.

## Limits

- Only embedded SCTs are checked; SCTs delivered in the TLS handshake or in OCSP aren't.
- The policy is Chrome's for embedded SCTs. Other browsers have their own, and Chrome's rules
  for SCTs sent in the TLS handshake differ.
- The log list's own signature isn't checked; it's fetched over HTTPS from Google.
- Each run trusts the latest tree head it fetches; it doesn't keep earlier ones to check that the
  log stays consistent over time, as a monitor would.

## License

MIT
