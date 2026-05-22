import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";

export const BSNS_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALKOeadEe3SYBncz7Q+EUO1QHpBW+ronwnuI7rwRAkpM=
-----END PUBLIC KEY-----`;

export const BSNS_SIGNING_KEY_ID = "267c8ae5dba95110";

export interface ManifestSigner {
  email: string;
  name: string;
  title: string | null;
  signedAt: string;
  ip: string;
}

export interface CertificateManifest {
  version: 1;
  issuer: string;
  documentId: string;
  ceremonyId: string;
  documentHash: string;
  documentName: string;
  signers: ManifestSigner[];
  completedAt: string;
  sameIpSigners: boolean;
}

export interface AttestationPacket {
  manifest: CertificateManifest;
  signature: string;
  signingKeyId: string;
  signingAlgorithm: "ed25519";
  ots?: {
    status: "absent" | "pending" | "bitcoin-anchored";
    receiptBase64: string | null;
  };
}

export interface VerificationResult {
  verdict: "verified" | "verified-unanchored" | "invalid";
  checks: {
    manifestSignature: "valid" | "invalid";
    signingKeyId: { claimed: string; actual: string; match: boolean };
    documentBinding: {
      status: "matched" | "mismatched" | "skipped";
      claimedHash: string;
      computedHash: string | null;
    };
    bitcoinAnchor: {
      status: "valid" | "pending" | "absent" | "failed" | "skipped";
      bitcoinBlockHeight: number | null;
      bitcoinTimestamp: string | null;
      message: string;
    };
  };
  manifest: CertificateManifest;
}

export interface VerifyOptions {
  publicKeyPem?: string;
  signedPdf?: Buffer | Uint8Array;
  verifyOts?: boolean;
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function fingerprintPublicKey(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

export async function verifyPacket(
  packet: AttestationPacket,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  assertPacketShape(packet);

  const publicKey = createPublicKey({
    key: options.publicKeyPem ?? BSNS_PUBLIC_KEY_PEM,
    format: "pem",
  });
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Verifier public key must be an Ed25519 key.");
  }

  const expectedKeyId = fingerprintPublicKey(publicKey);
  const keyIdMatch = expectedKeyId === packet.signingKeyId;

  let documentBinding: VerificationResult["checks"]["documentBinding"]["status"] =
    "skipped";
  let computedHash: string | null = null;
  if (options.signedPdf) {
    computedHash = createHash("sha256").update(options.signedPdf).digest("hex");
    documentBinding =
      computedHash === packet.manifest.documentHash ? "matched" : "mismatched";
  }

  const canonicalBytes = Buffer.from(canonicalize(packet.manifest), "utf8");
  const signatureValid = verify(
    null,
    canonicalBytes,
    publicKey,
    Buffer.from(packet.signature, "base64"),
  );

  const anchor = await verifyBitcoinAnchor(packet, options.verifyOts !== false);
  const baseValid =
    signatureValid &&
    keyIdMatch &&
    documentBinding !== "mismatched" &&
    anchor.status !== "failed";
  const verdict = !baseValid
    ? "invalid"
    : anchor.status === "pending" || anchor.status === "skipped"
      ? "verified-unanchored"
      : "verified";

  return {
    verdict,
    checks: {
      manifestSignature: signatureValid ? "valid" : "invalid",
      signingKeyId: {
        claimed: packet.signingKeyId,
        actual: expectedKeyId,
        match: keyIdMatch,
      },
      documentBinding: {
        status: documentBinding,
        claimedHash: packet.manifest.documentHash,
        computedHash,
      },
      bitcoinAnchor: anchor,
    },
    manifest: packet.manifest,
  };
}

function normalize(value: unknown): unknown {
  if (value === null) return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite numbers cannot be canonicalized.");
    }
    return value;
  }
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = normalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  throw new Error(`Cannot canonicalize value of type ${typeof value}.`);
}

function assertPacketShape(packet: AttestationPacket): void {
  if (!packet || typeof packet !== "object") {
    throw new Error("Attestation packet must be an object.");
  }
  if (!packet.manifest || typeof packet.manifest !== "object") {
    throw new Error("Attestation packet is missing manifest.");
  }
  if (packet.signingAlgorithm !== "ed25519") {
    throw new Error("Only Ed25519 pact attestations are supported.");
  }
  if (typeof packet.signature !== "string" || !packet.signature) {
    throw new Error("Attestation packet is missing signature.");
  }
  if (typeof packet.signingKeyId !== "string" || !packet.signingKeyId) {
    throw new Error("Attestation packet is missing signingKeyId.");
  }
  if (typeof packet.manifest.documentHash !== "string") {
    throw new Error("Manifest is missing documentHash.");
  }
}

async function verifyBitcoinAnchor(
  packet: AttestationPacket,
  shouldVerify: boolean,
): Promise<VerificationResult["checks"]["bitcoinAnchor"]> {
  const receiptBase64 = packet.ots?.receiptBase64 ?? null;
  if (!receiptBase64) {
    return {
      status: packet.ots?.status === "pending" ? "pending" : "absent",
      bitcoinBlockHeight: null,
      bitcoinTimestamp: null,
      message:
        packet.ots?.status === "pending"
          ? "Calendar submission pending; no Bitcoin receipt is available yet."
          : "No OpenTimestamps receipt is present in this packet.",
    };
  }
  if (!shouldVerify) {
    return {
      status: "skipped",
      bitcoinBlockHeight: null,
      bitcoinTimestamp: null,
      message: "OpenTimestamps verification was skipped.",
    };
  }

  try {
    const ots = await loadOts();
    const receiptBytes = Buffer.from(receiptBase64, "base64");
    const stamped = ots.DetachedTimestampFile.deserialize(
      new ots.Context.StreamDeserialization(receiptBytes),
    );
    const original = ots.DetachedTimestampFile.fromHash(
      new ots.Ops.OpSHA256(),
      Buffer.from(packet.manifest.documentHash, "hex"),
    );
    const results = await ots.verify(stamped, original);
    const bitcoin = results?.bitcoin;
    if (bitcoin) {
      return {
        status: "valid",
        bitcoinBlockHeight: bitcoin.height,
        bitcoinTimestamp: new Date(bitcoin.timestamp * 1000).toISOString(),
        message: `Anchored in Bitcoin block ${bitcoin.height}.`,
      };
    }
    return {
      status: "pending",
      bitcoinBlockHeight: null,
      bitcoinTimestamp: null,
      message: "Receipt is calendar-only; not yet anchored to Bitcoin.",
    };
  } catch (error) {
    return {
      status: "failed",
      bitcoinBlockHeight: null,
      bitcoinTimestamp: null,
      message: error instanceof Error ? error.message : "OTS verification failed.",
    };
  }
}

type OtsLib = {
  verify: (
    detached: unknown,
    original: unknown,
    options?: unknown,
  ) => Promise<Record<string, { timestamp: number; height: number }>>;
  DetachedTimestampFile: {
    fromHash: (op: unknown, hash: Buffer) => unknown;
    deserialize: (buffer: unknown) => unknown;
  };
  Ops: { OpSHA256: new () => unknown };
  Context: { StreamDeserialization: new (bytes: Buffer) => unknown };
};

let otsPromise: Promise<OtsLib> | null = null;

async function loadOts(): Promise<OtsLib> {
  otsPromise ??= import("opentimestamps").then(
    (module) => (module.default ?? module) as unknown as OtsLib,
  );
  return otsPromise;
}
