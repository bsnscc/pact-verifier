# pact verifier

Standalone verifier for pact certificate attestation packets issued by bsns.cc.

The verifier does not need access to bsns.cc. It uses the pinned bsns.cc Ed25519
public key by default:

```text
Key ID: 267c8ae5dba95110
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALKOeadEe3SYBncz7Q+EUO1QHpBW+ronwnuI7rwRAkpM=
-----END PUBLIC KEY-----
```

## What It Checks

- The attestation manifest signature is valid for the issuer public key.
- The `signingKeyId` in the packet matches the public key fingerprint.
- The signed PDF hash matches `manifest.documentHash`, when a PDF is supplied.
- The OpenTimestamps receipt is anchored to Bitcoin, when a receipt is present.

This verifies cryptographic integrity. It does not independently prove that the
people or business facts named in a certificate are true.

## CLI

```sh
npm install
npm run build
node dist/cli.js attestation.json signed-document.pdf
```

If you only have the attestation packet:

```sh
node dist/cli.js attestation.json
```

That still verifies the manifest signature and any OpenTimestamps receipt, but
it cannot prove that a PDF in your possession matches the manifest.

Useful options:

```sh
node dist/cli.js --json attestation.json signed-document.pdf
node dist/cli.js --no-ots attestation.json signed-document.pdf
node dist/cli.js --public-key issuer.pem attestation.json signed-document.pdf
```

Exit codes:

- `0`: fully verified.
- `1`: invalid signature, key mismatch, PDF hash mismatch, or failed OTS check.
- `2`: signature/key/hash checks passed, but the Bitcoin anchor is pending or
  OTS verification was skipped.

## Local Web Verifier

```sh
npm install
npm run build
npm start
```

Then open:

```text
http://localhost:4177
```

The local web verifier accepts an `attestation.json` packet and an optional
signed PDF. It runs on your machine and does not upload files to bsns.cc.

## Attestation Packet Shape

```json
{
  "manifest": {
    "version": 1,
    "issuer": "https://pact.bsns.cc",
    "documentId": "doc_...",
    "ceremonyId": "ceremony_...",
    "documentHash": "sha256 hex of the signed PDF",
    "documentName": "Agreement.pdf",
    "signers": [
      {
        "email": "person@example.com",
        "name": "Person Example",
        "title": null,
        "signedAt": "2026-05-22T12:00:00.000Z",
        "ip": "203.0.113.10"
      }
    ],
    "completedAt": "2026-05-22T12:01:00.000Z",
    "sameIpSigners": false
  },
  "signature": "base64 Ed25519 signature over canonical manifest JSON",
  "signingKeyId": "267c8ae5dba95110",
  "signingAlgorithm": "ed25519",
  "ots": {
    "status": "bitcoin-anchored",
    "receiptBase64": "base64 OpenTimestamps receipt"
  }
}
```

Manifest signatures are computed over canonical JSON: object keys are sorted
recursively and no whitespace is added.

## Development

```sh
npm install
npm run verify
```

OpenTimestamps verification is isolated to the verification path. If you deploy
this as a hosted service, keep dependencies pinned, run regular dependency
reviews, and consider disabling OTS verification for untrusted high-volume
traffic.
