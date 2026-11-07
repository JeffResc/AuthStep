// Minimal DER, PKCS#10 and PKCS#12 encoding on top of WebCrypto.
//
// All cryptography (key generation, ECDSA, PBKDF2, AES, SHA-256, HMAC) is done
// by WebCrypto; this module only builds the ASN.1 structures around it.
// It works in browsers and in Node (which provides globalThis.crypto).

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

// PBKDF2 and MAC iteration counts match OpenSSL 3's PKCS#12 defaults. The
// passphrase is 80 random bits, so the count adds little and costs
// compatibility when raised.
const ITERATIONS = 2048;

// ---- DER ----

export function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function lengthBytes(n) {
  if (n < 0x80) return [n];
  const b = [];
  for (; n > 0; n = Math.floor(n / 256)) b.unshift(n & 0xff);
  return [0x80 | b.length, ...b];
}

function tlv(tag, ...parts) {
  const body = concat(parts);
  return concat([Uint8Array.of(tag, ...lengthBytes(body.length)), body]);
}

const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p); // single-element sets only, so no DER sorting is needed
const octets = (b) => tlv(0x04, b);
const nul = () => Uint8Array.of(0x05, 0x00);
const utf8String = (s) => tlv(0x0c, utf8.encode(s));
const explicit = (n, ...p) => tlv(0xa0 | n, ...p);

function bmpString(s) {
  const b = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    b[2 * i] = s.charCodeAt(i) >> 8;
    b[2 * i + 1] = s.charCodeAt(i) & 0xff;
  }
  return b;
}

// integer encodes a non-negative integer given as a number or big-endian bytes.
function integer(v) {
  let b = v;
  if (typeof v === "number") {
    const digits = [];
    do {
      digits.unshift(v & 0xff);
      v = Math.floor(v / 256);
    } while (v > 0);
    b = Uint8Array.from(digits);
  }
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = concat([Uint8Array.of(0), b]);
  return tlv(0x02, b);
}

function oid(dotted) {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const out = [40 * a + b];
  for (const n of rest) {
    const groups = [];
    let v = n;
    do {
      groups.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < groups.length - 1; i++) groups[i] |= 0x80;
    out.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(out));
}

const OID = {
  commonName: "2.5.4.3",
  subjectAltName: "2.5.29.17",
  extensionRequest: "1.2.840.113549.1.9.14",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  data: "1.2.840.113549.1.7.1",
  pkcs8ShroudedKeyBag: "1.2.840.113549.1.12.10.1.2",
  certBag: "1.2.840.113549.1.12.10.1.3",
  x509Certificate: "1.2.840.113549.1.9.22.1",
  friendlyName: "1.2.840.113549.1.9.20",
  localKeyId: "1.2.840.113549.1.9.21",
  pbes2: "1.2.840.113549.1.5.13",
  pbkdf2: "1.2.840.113549.1.5.12",
  hmacWithSHA256: "1.2.840.113549.2.9",
  aes256CBC: "2.16.840.1.101.3.4.1.42",
  sha256: "2.16.840.1.101.3.4.2.1",
};

// ---- Keys and CSR ----

export function generateKey() {
  // Extractable so the private key can be written into the .p12 file.
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}

// buildCSR returns a DER PKCS#10 request with subject CN=email and a SAN
// extension holding exactly email and deviceURI.
export async function buildCSR(keyPair, email, deviceURI) {
  const spki = new Uint8Array(await subtle.exportKey("spki", keyPair.publicKey));
  const generalNames = seq(tlv(0x81, utf8.encode(email)), tlv(0x86, utf8.encode(deviceURI)));
  const extensions = seq(seq(oid(OID.subjectAltName), octets(generalNames)));
  const info = seq(
    integer(0),
    seq(set(seq(oid(OID.commonName), utf8String(email)))),
    spki,
    tlv(0xa0, seq(oid(OID.extensionRequest), set(extensions))),
  );
  const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, info));
  return seq(info, seq(oid(OID.ecdsaWithSHA256)), tlv(0x03, Uint8Array.of(0), ecdsaSigToDER(raw)));
}

// WebCrypto returns ECDSA signatures as r||s; X.509 wants SEQUENCE { r, s }.
function ecdsaSigToDER(raw) {
  const half = raw.length / 2;
  return seq(integer(raw.subarray(0, half)), integer(raw.subarray(half)));
}

// ---- PKCS#12 ----

// buildPKCS12 returns a DER PFX holding the PKCS#8 private key (PBES2:
// PBKDF2-HMAC-SHA256 + AES-256-CBC) and the certificates, protected by an
// HMAC-SHA256 MAC. certs[0] must be the certificate for the key.
export async function buildPKCS12({ privateKeyPKCS8, certs, friendlyName, passphrase }) {
  const localKeyId = new Uint8Array(await subtle.digest("SHA-256", certs[0]));
  // The key and its certificate share localKeyId so importers pair them.
  const bagAttributes = tlv(
    0x31,
    ...sortDER([
      seq(oid(OID.friendlyName), set(tlv(0x1e, bmpString(friendlyName)))),
      seq(oid(OID.localKeyId), set(octets(localKeyId))),
    ]),
  );

  const keyBag = seq(
    oid(OID.pkcs8ShroudedKeyBag),
    explicit(0, await encryptPrivateKey(privateKeyPKCS8, passphrase)),
    bagAttributes,
  );
  const certBags = certs.map((der, i) =>
    seq(
      oid(OID.certBag),
      explicit(0, seq(oid(OID.x509Certificate), explicit(0, octets(der)))),
      ...(i === 0 ? [bagAttributes] : []),
    ),
  );

  const dataContentInfo = (safeContents) => seq(oid(OID.data), explicit(0, octets(safeContents)));
  const authSafe = seq(dataContentInfo(seq(keyBag)), dataContentInfo(seq(...certBags)));

  const macSalt = randomBytes(16);
  const macKey = await pkcs12KDF(passphrase, macSalt, 3, ITERATIONS, 32);
  const hmacKey = await subtle.importKey("raw", macKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await subtle.sign("HMAC", hmacKey, authSafe));
  const macData = seq(seq(seq(oid(OID.sha256), nul()), octets(mac)), octets(macSalt), integer(ITERATIONS));

  return seq(integer(3), dataContentInfo(authSafe), macData);
}

async function encryptPrivateKey(pkcs8, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const base = await subtle.importKey("raw", utf8.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );
  const encrypted = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key, pkcs8));
  const algorithm = seq(
    oid(OID.pbes2),
    seq(
      seq(oid(OID.pbkdf2), seq(octets(salt), integer(ITERATIONS), seq(oid(OID.hmacWithSHA256), nul()))),
      seq(oid(OID.aes256CBC), octets(iv)),
    ),
  );
  return seq(algorithm, octets(encrypted));
}

// pkcs12KDF implements RFC 7292 appendix B.2 with SHA-256 (u = 32, v = 64).
export async function pkcs12KDF(passphrase, salt, id, iterations, n) {
  const u = 32;
  const v = 64;
  const pw = concat([bmpString(passphrase), Uint8Array.of(0, 0)]);
  const fill = (src) => {
    const out = new Uint8Array(v * Math.ceil(src.length / v));
    for (let i = 0; i < out.length; i++) out[i] = src[i % src.length];
    return out;
  };
  const D = new Uint8Array(v).fill(id);
  const I = concat([salt.length ? fill(salt) : new Uint8Array(0), pw.length ? fill(pw) : new Uint8Array(0)]);

  const out = new Uint8Array(Math.ceil(n / u) * u);
  for (let i = 0; i * u < n; i++) {
    let A = new Uint8Array(await subtle.digest("SHA-256", concat([D, I])));
    for (let r = 1; r < iterations; r++) A = new Uint8Array(await subtle.digest("SHA-256", A));
    out.set(A, i * u);

    const B = fill(A).subarray(0, v);
    for (let j = 0; j < I.length; j += v) {
      // I_j = (I_j + B + 1) mod 2^(8v)
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const sum = I[j + k] + B[k] + carry;
        I[j + k] = sum & 0xff;
        carry = sum >> 8;
      }
    }
  }
  return out.subarray(0, n);
}

// sortDER orders encodings for a DER SET OF.
function sortDER(items) {
  return [...items].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });
}

// ---- Helpers ----

function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// generatePassphrase returns 16 characters (80 bits) in groups of four, from
// an alphabet without look-alike characters, e.g. "7KQM-2XRP-H9TD-VW4N".
export function generatePassphrase() {
  const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 symbols: 256 % 32 == 0, so no modulo bias
  const groups = [];
  for (const b of randomBytes(16)) {
    if (groups.length === 0 || groups.at(-1).length === 4) groups.push("");
    groups[groups.length - 1] += alphabet[b & 31];
  }
  return groups.join("-");
}

export function base64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function pem(type, der) {
  const lines = base64(der).match(/.{1,64}/g);
  return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----\n`;
}

export function pemToDER(text) {
  const b64 = text.replace(/-----(BEGIN|END) [^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
