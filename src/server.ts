#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { verifyPacket, type AttestationPacket } from "./index.js";

const port = Number(process.env.PORT ?? 4177);

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(pageHtml);
      return;
    }

    if (request.method === "POST" && request.url === "/verify") {
      const body = JSON.parse(await readBody(request)) as {
        packet: AttestationPacket;
        signedPdfBase64?: string;
        publicKeyPem?: string;
        verifyOts?: boolean;
      };
      const result = await verifyPacket(body.packet, {
        signedPdf: body.signedPdfBase64
          ? Buffer.from(body.signedPdfBase64, "base64")
          : undefined,
        publicKeyPem: body.publicKeyPem,
        verifyOts: body.verifyOts,
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(result, null, 2));
      return;
    }

    if (request.method === "GET" && request.url === "/.well-known/pact-signing-key.json") {
      const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
        version: string;
      };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify(
          {
            issuer: "https://pact.bsns.cc",
            algorithm: "Ed25519",
            keyId: "267c8ae5dba95110",
            publicKeyPem:
              "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEALKOeadEe3SYBncz7Q+EUO1QHpBW+ronwnuI7rwRAkpM=\n-----END PUBLIC KEY-----",
            verifierVersion: packageJson.version,
          },
          null,
          2,
        ),
      );
      return;
    }

    response.writeHead(404, { "content-type": "text/plain" });
    response.end("Not found");
  } catch (error) {
    response.writeHead(500, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        error: error instanceof Error ? error.message : "Verification failed",
      }),
    );
  }
});

server.listen(port, () => {
  console.log(`pact verifier listening on http://localhost:${port}`);
});

function readBody(request: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

const pageHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>pact verifier</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f6f5f2; color: #171717; }
    main { width: min(860px, calc(100% - 32px)); margin: 40px auto; }
    header { text-align: center; margin-bottom: 28px; }
    h1 { font-size: 22px; margin: 0; }
    .brand { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
    .panel { background: white; border: 1px solid #ddd8ce; border-radius: 8px; padding: 24px; }
    label { display: block; font-size: 12px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; margin: 18px 0 8px; color: #595651; }
    textarea { width: 100%; min-height: 140px; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; border: 1px solid #cfc9bd; border-radius: 6px; padding: 10px; }
    button { margin-top: 18px; height: 38px; padding: 0 18px; border: 0; border-radius: 6px; background: #111; color: #fff; font-weight: 700; cursor: pointer; }
    button:disabled { opacity: .5; cursor: wait; }
    pre { overflow: auto; background: #111; color: #f5f5f5; padding: 14px; border-radius: 6px; font-size: 12px; }
    .hint, li { color: #595651; line-height: 1.45; }
    .verdict { margin-top: 18px; padding: 12px; border-radius: 6px; font-weight: 700; }
    .verified { background: #e8f7ee; color: #176136; border: 1px solid #9ed8b5; }
    .invalid { background: #fdecec; color: #8a1f1f; border: 1px solid #efb0b0; }
    @media (prefers-color-scheme: dark) {
      body { background: #161514; color: #f6f5f2; }
      .panel { background: #211f1c; border-color: #3c3832; }
      textarea { background: #151515; color: #f5f5f5; border-color: #555; }
      .hint, li, label { color: #b8b1a6; }
      button { background: #f4f1ea; color: #111; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="brand">pact.</div>
      <div class="hint">certificate verification</div>
    </header>
    <section class="panel">
      <h1>Verify a pact certificate</h1>
      <p class="hint">Drop the attestation JSON and optionally the signed PDF. The verifier runs locally against the pinned bsns.cc public key.</p>
      <ul>
        <li>Checks the Ed25519 manifest signature.</li>
        <li>Checks the signed PDF SHA-256 hash when a PDF is provided.</li>
        <li>Checks the OpenTimestamps Bitcoin receipt when present.</li>
      </ul>
      <label>Attestation packet (.json)</label>
      <input id="packetFile" type="file">
      <textarea id="packetText" placeholder="or paste attestation.json here"></textarea>
      <label>Signed PDF (optional)</label>
      <input id="pdfFile" type="file" accept="application/pdf,.pdf">
      <label><input id="verifyOts" type="checkbox" checked> Verify OpenTimestamps receipt</label>
      <button id="verifyButton">Verify</button>
      <div id="verdict"></div>
      <pre id="output" hidden></pre>
    </section>
  </main>
  <script>
    const packetFile = document.querySelector("#packetFile");
    const packetText = document.querySelector("#packetText");
    const pdfFile = document.querySelector("#pdfFile");
    const button = document.querySelector("#verifyButton");
    const output = document.querySelector("#output");
    const verdict = document.querySelector("#verdict");
    packetFile.addEventListener("change", async () => {
      if (packetFile.files[0]) packetText.value = await packetFile.files[0].text();
    });
    async function fileToBase64(file) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(binary);
    }
    button.addEventListener("click", async () => {
      button.disabled = true;
      verdict.textContent = "";
      verdict.className = "";
      output.hidden = true;
      try {
        const body = {
          packet: JSON.parse(packetText.value),
          verifyOts: document.querySelector("#verifyOts").checked
        };
        if (pdfFile.files[0]) body.signedPdfBase64 = await fileToBase64(pdfFile.files[0]);
        const response = await fetch("/verify", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Verification failed");
        verdict.textContent = "Verdict: " + result.verdict;
        verdict.className = "verdict " + (result.verdict === "invalid" ? "invalid" : "verified");
        output.textContent = JSON.stringify(result, null, 2);
        output.hidden = false;
      } catch (error) {
        verdict.textContent = error.message || String(error);
        verdict.className = "verdict invalid";
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>`;
