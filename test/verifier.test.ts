import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BSNS_PUBLIC_KEY_PEM,
  BSNS_SIGNING_KEY_ID,
  canonicalize,
  fingerprintPublicKey,
  verifyPacket,
  type AttestationPacket,
  type CertificateManifest,
} from "../src/index.js";

describe("pact verifier", () => {
  it("fingerprints the pinned bsns.cc public key", () => {
    expect(fingerprintPublicKey(createPublicKey(BSNS_PUBLIC_KEY_PEM))).toBe(
      BSNS_SIGNING_KEY_ID,
    );
  });

  it("verifies a signed manifest and matching PDF hash", async () => {
    const { packet, publicKeyPem, pdfBytes } = createFixture();
    const result = await verifyPacket(packet, {
      publicKeyPem,
      signedPdf: pdfBytes,
      verifyOts: false,
    });

    expect(result.verdict).toBe("verified");
    expect(result.checks.manifestSignature).toBe("valid");
    expect(result.checks.documentBinding.status).toBe("matched");
    expect(result.checks.signingKeyId.match).toBe(true);
  });

  it("rejects a tampered manifest", async () => {
    const { packet, publicKeyPem, pdfBytes } = createFixture();
    packet.manifest.documentName = "tampered.pdf";

    const result = await verifyPacket(packet, {
      publicKeyPem,
      signedPdf: pdfBytes,
      verifyOts: false,
    });

    expect(result.verdict).toBe("invalid");
    expect(result.checks.manifestSignature).toBe("invalid");
  });

  it("detects a mismatched PDF", async () => {
    const { packet, publicKeyPem } = createFixture();
    const result = await verifyPacket(packet, {
      publicKeyPem,
      signedPdf: Buffer.from("not the signed pdf"),
      verifyOts: false,
    });

    expect(result.verdict).toBe("invalid");
    expect(result.checks.documentBinding.status).toBe("mismatched");
  });
});

function createFixture(): {
  packet: AttestationPacket;
  publicKeyPem: string;
  pdfBytes: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const pdfBytes = Buffer.from("%PDF-1.4\nfixture\n%%EOF\n");
  const manifest: CertificateManifest = {
    version: 1,
    issuer: "https://pact.bsns.cc",
    documentId: "doc_test",
    ceremonyId: "ceremony_test",
    documentHash: createHash("sha256").update(pdfBytes).digest("hex"),
    documentName: "fixture.pdf",
    signers: [
      {
        email: "alice@example.com",
        name: "Alice Example",
        title: null,
        signedAt: "2026-05-22T12:00:00.000Z",
        ip: "203.0.113.10",
      },
    ],
    completedAt: "2026-05-22T12:01:00.000Z",
    sameIpSigners: false,
  };

  return {
    packet: {
      manifest,
      signature: sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString(
        "base64",
      ),
      signingKeyId: fingerprintPublicKey(publicKey),
      signingAlgorithm: "ed25519",
      ots: { status: "absent", receiptBase64: null },
    },
    publicKeyPem,
    pdfBytes,
  };
}
