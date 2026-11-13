// Embedded SCTs (RFC 6962 section 3.3): reads them from a certificate, and rebuilds the two
// structures a log hashed for them: the signed CertificateTimestamp and the Merkle tree leaf.
// Both cover the precertificate's TBSCertificate, which is the certificate's own TBSCertificate
// with the SCT list extension taken out, and the hash of the issuer's public key.

import { createHash } from "node:crypto";

import { EXTENSIONS, OCTET_STRING, OID, SEQUENCE, VERSION, children, encode, read, same } from "./der.ts";

/** 1.3.6.1.4.1.11129.2.4.2, the embedded SCT list extension. */
const SCT_LIST = Uint8Array.of(0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02);
const LEAF_INDEX = 0; // static-ct-api's CtExtensionType for leaf_index
const PRECERT_ENTRY = 1;

export interface Sct {
  logId: Buffer;
  timestamp: number; // milliseconds since the epoch
  extensions: Buffer;
  /** The TLS DigitallySigned structure: hash and signature algorithms, then the signature. */
  signature: Buffer;
  /** Where a static-ct-api log put the entry, from its leaf_index extension. */
  leafIndex?: number;
}

export interface Embedded {
  scts: Sct[];
  /** The precertificate's TBSCertificate, which every SCT covers. */
  tbs: Buffer;
}

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

function tbsOf(der: Uint8Array) {
  const certificate = read(der, 0);
  if (certificate.tag !== SEQUENCE || certificate.end !== der.length) throw new Error("not a DER certificate");
  const tbs = children(der, certificate)[0];
  if (tbs?.tag !== SEQUENCE) throw new Error("not a DER certificate");
  return { tbs, fields: children(der, tbs) };
}

/** SHA-256 of the issuer's SubjectPublicKeyInfo, exactly as encoded in its certificate. */
export function issuerKeyHash(issuer: Uint8Array): Buffer {
  const { fields } = tbsOf(issuer);
  const spki = fields[fields[0]?.tag === VERSION ? 6 : 5];
  if (spki?.tag !== SEQUENCE) throw new Error("issuer certificate has no public key");
  return sha256(issuer.subarray(spki.at, spki.end));
}

/** The SCTs embedded in a certificate, and the TBSCertificate they cover. */
export function embedded(der: Uint8Array): Embedded {
  const { tbs, fields } = tbsOf(der);
  const wrapper = fields.at(-1);
  const list = wrapper?.tag === EXTENSIONS ? children(der, wrapper)[0] : undefined;
  if (!wrapper || !list) return { scts: [], tbs: Buffer.from(der.subarray(tbs.at, tbs.end)) };
  if (list.tag !== SEQUENCE) throw new Error("malformed certificate extensions");

  const extensions = children(der, list);
  const found = extensions.find((extension) => {
    const oid = children(der, extension)[0];
    return oid?.tag === OID && same(der.subarray(oid.start, oid.end), SCT_LIST);
  });
  if (!found) return { scts: [], tbs: Buffer.from(der.subarray(tbs.at, tbs.end)) };

  const value = children(der, found).at(-1); // after an optional critical flag
  if (value?.tag !== OCTET_STRING) throw new Error("malformed SCT list extension");
  const inner = read(der, value.start);
  if (inner.tag !== OCTET_STRING || inner.end !== value.end) throw new Error("malformed SCT list extension");

  // Rebuild the TBSCertificate without the extension: the list, its [3] wrapper and the TBS
  // itself all get new lengths, and everything else stays byte for byte.
  const rest = extensions.filter((extension) => extension !== found).map((extension) => der.subarray(extension.at, extension.end));
  const precertTbs = encode(SEQUENCE, Buffer.concat([der.subarray(tbs.start, wrapper.at), encode(EXTENSIONS, encode(SEQUENCE, Buffer.concat(rest)))]));
  return { scts: parseList(Buffer.from(der.subarray(inner.start, inner.end))), tbs: precertTbs };
}

/** A TLS-encoded SignedCertificateTimestampList. */
export function parseList(list: Buffer): Sct[] {
  const scts: Sct[] = [];
  const take = (buffer: Buffer, at: number, n: number) => {
    if (at + n > buffer.length) throw new Error("truncated SCT list");
    return buffer.subarray(at, at + n);
  };
  const total = take(list, 0, 2).readUInt16BE();
  if (total !== list.length - 2) throw new Error("SCT list length doesn't match");
  for (let at = 2; at < list.length; ) {
    const length = take(list, at, 2).readUInt16BE();
    const sct = take(list, at + 2, length);
    at += 2 + length;
    if (sct[0] !== 0) throw new Error(`unknown SCT version ${sct[0]}`);
    const logId = take(sct, 1, 32);
    const timestamp = Number(take(sct, 33, 8).readBigUInt64BE());
    const extensionsLength = take(sct, 41, 2).readUInt16BE();
    const extensions = take(sct, 43, extensionsLength);
    const signature = sct.subarray(43 + extensionsLength);
    if (signature.length < 4 || signature.readUInt16BE(2) !== signature.length - 4) throw new Error("malformed SCT signature");
    scts.push({ logId: Buffer.from(logId), timestamp, extensions: Buffer.from(extensions), signature: Buffer.from(signature), leafIndex: leafIndex(extensions) });
  }
  return scts;
}

/** The leaf_index extension of static-ct-api, a 40-bit big-endian integer, if present. */
function leafIndex(extensions: Buffer): number | undefined {
  for (let at = 0; at + 3 <= extensions.length; ) {
    const type = extensions[at];
    const length = extensions.readUInt16BE(at + 1);
    if (at + 3 + length > extensions.length) throw new Error("malformed SCT extensions");
    if (type === LEAF_INDEX) {
      if (length !== 5) throw new Error("malformed leaf_index extension");
      return extensions.readUIntBE(at + 3, 5);
    }
    at += 3 + length;
  }
  return undefined;
}

const u8 = (n: number) => Uint8Array.of(n);
const u16 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);
const u24 = (n: number) => Uint8Array.of(n >> 16, (n >> 8) & 0xff, n & 0xff);
function u64(n: number) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n));
  return out;
}

/** timestamp, entry_type, PreCert and extensions: shared by both structures below. */
function timestampedEntry(sct: Sct, issuerKey: Buffer, tbs: Buffer) {
  return Buffer.concat([u64(sct.timestamp), u16(PRECERT_ENTRY), issuerKey, u24(tbs.length), tbs, u16(sct.extensions.length), sct.extensions]);
}

/** What the log signed: version v1, signature_type certificate_timestamp, then the entry. */
export const signedData = (sct: Sct, issuerKey: Buffer, tbs: Buffer) => Buffer.concat([u8(0), u8(0), timestampedEntry(sct, issuerKey, tbs)]);

/** The Merkle tree leaf hash: version v1 and leaf_type timestamped_entry, hashed with prefix 0. */
export const leafHash = (sct: Sct, issuerKey: Buffer, tbs: Buffer) => sha256(u8(0), u8(0), u8(0), timestampedEntry(sct, issuerKey, tbs));
