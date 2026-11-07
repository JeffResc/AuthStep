// Tests for static/js/pkix.js. Output is checked with the openssl CLI.
// Run: node --test internal/web/jstest/*.test.mjs
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildCSR, buildPKCS12, generateKey, generatePassphrase, pem, pemToDER } from "../static/js/pkix.js";

const dir = mkdtempSync(join(tmpdir(), "authstep-pkix-"));
// openssl returns stdout and stderr together; some subcommands report on stderr.
function openssl(...args) {
  const r = spawnSync("openssl", args, { encoding: "utf8" });
  const out = r.stdout + r.stderr;
  if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${out}`);
  return out;
}

const pemBlock = (text, type) => text.match(new RegExp(`-----BEGIN ${type}-----[\\s\\S]+?-----END ${type}-----\\n`))[0];

const email = "alice@example.com";
const deviceURI = "urn:authstep:device:0b3c9a52-4f8e-4d4e-9d6b-2f0c8e7a1c55";

async function issued() {
  const keys = await generateKey();
  const csr = await buildCSR(keys, email, deviceURI);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey));
  const f = (name, data) => {
    const p = join(dir, `${Math.random().toString(36).slice(2)}-${name}`);
    writeFileSync(p, data);
    return p;
  };
  const csrPath = f("req.pem", pem("CERTIFICATE REQUEST", csr));
  const keyPath = f("key.pem", pem("PRIVATE KEY", pkcs8));
  // Self-sign the CSR so we have a certificate that matches the key.
  const certPEM = openssl("x509", "-req", "-in", csrPath, "-key", keyPath, "-days", "1", "-copy_extensions", "copy");
  return { csr, csrPath, pkcs8, cert: pemToDER(pemBlock(certPEM, "CERTIFICATE")), f };
}

test("CSR verifies and carries exactly the requested identity", async () => {
  const { csrPath } = await issued();
  const text = openssl("req", "-in", csrPath, "-verify", "-noout", "-text");
  assert.match(text, /Subject: CN\s*=\s*alice@example\.com\n/);
  assert.match(text, /ASN1 OID: prime256v1/);
  assert.match(text, /X509v3 Subject Alternative Name:\s*\n\s*email:alice@example\.com, URI:urn:authstep:device:0b3c9a52-4f8e-4d4e-9d6b-2f0c8e7a1c55\n/);
  assert.match(text, /Signature Algorithm: ecdsa-with-SHA256/);
});

test("PKCS#12 opens with the passphrase and holds the matching key and certificate", async () => {
  const { pkcs8, cert, f } = await issued();
  const passphrase = generatePassphrase();
  const p12 = await buildPKCS12({ privateKeyPKCS8: pkcs8, certs: [cert], friendlyName: "Work laptop", passphrase });
  const p12Path = f("bundle.p12", p12);

  const info = openssl("pkcs12", "-in", p12Path, "-info", "-noout", "-passin", `pass:${passphrase}`);
  assert.match(info, /MAC: sha256, Iteration 2048/);
  assert.match(info, /Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256/);

  const out = openssl("pkcs12", "-in", p12Path, "-nodes", "-passin", `pass:${passphrase}`);
  assert.match(out, /friendlyName: Work laptop/);
  const keyOut = f("out-key.pem", pemBlock(out, "PRIVATE KEY"));
  const certOut = f("out-cert.pem", pemBlock(out, "CERTIFICATE"));
  assert.deepEqual(pemToDER(pemBlock(openssl("pkey", "-in", keyOut), "PRIVATE KEY")), pkcs8);
  assert.equal(
    pemBlock(openssl("pkey", "-in", keyOut, "-pubout"), "PUBLIC KEY"),
    pemBlock(openssl("x509", "-in", certOut, "-noout", "-pubkey"), "PUBLIC KEY"),
  );
});

test("PKCS#12 rejects a wrong passphrase", async () => {
  const { pkcs8, cert, f } = await issued();
  const p12 = await buildPKCS12({ privateKeyPKCS8: pkcs8, certs: [cert], friendlyName: "x", passphrase: generatePassphrase() });
  const p12Path = f("bundle.p12", p12);
  assert.throws(() => openssl("pkcs12", "-in", p12Path, "-info", "-noout", "-passin", "pass:WRONG-WRONG-WRONG-WRON"), /mac verify error/i);
});

test("passphrase is four groups of four unambiguous characters", () => {
  for (let i = 0; i < 100; i++) {
    assert.match(generatePassphrase(), /^[2-9A-HJ-NP-Z]{4}(-[2-9A-HJ-NP-Z]{4}){3}$/);
  }
});
