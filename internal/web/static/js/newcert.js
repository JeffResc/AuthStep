import { base64, buildCSR, buildPKCS12, generateKey, generatePassphrase, pem, pemToDER } from "./pkix.js";

const root = document.getElementById("newcert");
const form = document.getElementById("request-form");
const progress = document.getElementById("progress");
const errorBox = document.getElementById("error");
const result = document.getElementById("result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const deviceName = form.deviceName.value.trim();
  form.querySelector("button").disabled = true;
  errorBox.hidden = true;
  try {
    show(progress, "Reserving your certificate…");
    const reservation = await post("/api/certs", { deviceName });

    show(progress, "Creating your private key…");
    const keys = await generateKey();
    const csr = await buildCSR(keys, reservation.email, reservation.deviceURI);

    show(progress, "Requesting your certificate…");
    const issued = await post(`/api/certs/${encodeURIComponent(reservation.id)}/csr`, { csr: base64(csr) });
    const certs = [issued.certificate, ...issued.chain].map(pemToDER);

    show(progress, "Packaging your certificate…");
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey));
    const passphrase = generatePassphrase();
    const p12 = await buildPKCS12({ privateKeyPKCS8: pkcs8, certs, friendlyName: deviceName, passphrase });

    const name = fileName(deviceName);
    link("download-p12", `${name}.p12`, p12);
    // The same PKCS#12 file under the extension Windows associates with it.
    link("download-pfx", `${name}.pfx`, p12);
    link("download-pem", `${name}.pem`, certs.map((c) => pem("CERTIFICATE", c)).join(""));
    link("download-key", `${name}.key.pem`, pem("PRIVATE KEY", pkcs8));
    document.getElementById("passphrase").value = passphrase;

    form.hidden = true;
    progress.hidden = true;
    result.hidden = false;
  } catch (err) {
    progress.hidden = true;
    show(errorBox, err.message);
    form.querySelector("button").disabled = false;
  }
});

document.getElementById("copy-passphrase").addEventListener("click", async (event) => {
  await navigator.clipboard.writeText(document.getElementById("passphrase").value);
  event.target.textContent = "Copied";
});

async function post(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status}).`);
  return data;
}

function show(el, text) {
  el.textContent = text;
  el.hidden = false;
}

// application/octet-stream makes iOS Safari save the file to Files. With a
// certificate MIME type, iOS opens it as a configuration profile, and apps
// such as Home Assistant and Immich then cannot import it.
function link(id, filename, content) {
  const a = document.getElementById(id);
  a.href = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
  a.download = filename;
}

function fileName(deviceName) {
  return deviceName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "certificate";
}
