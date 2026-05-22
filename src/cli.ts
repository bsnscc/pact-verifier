#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyPacket, type AttestationPacket } from "./index.js";

interface CliOptions {
  packetPath: string | null;
  pdfPath: string | null;
  publicKeyPath: string | null;
  json: boolean;
  verifyOts: boolean;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (!options.packetPath) {
    printUsage();
    process.exitCode = 64;
    return;
  }

  const packet = JSON.parse(
    await readFile(options.packetPath, "utf8"),
  ) as AttestationPacket;
  const signedPdf = options.pdfPath ? await readFile(options.pdfPath) : undefined;
  const publicKeyPem = options.publicKeyPath
    ? await readFile(options.publicKeyPath, "utf8")
    : undefined;

  const result = await verifyPacket(packet, {
    signedPdf,
    publicKeyPem,
    verifyOts: options.verifyOts,
  });

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printSummary(result);
  }

  process.exitCode =
    result.verdict === "verified"
      ? 0
      : result.verdict === "verified-unanchored"
        ? 2
        : 1;
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    packetPath: null,
    pdfPath: null,
    publicKeyPath: null,
    json: false,
    verifyOts: true,
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--no-ots") {
      options.verifyOts = false;
    } else if (arg === "--public-key") {
      options.publicKeyPath = args[++i] ?? null;
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else if (!options.packetPath) {
      options.packetPath = arg;
    } else if (!options.pdfPath) {
      options.pdfPath = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  return options;
}

function printSummary(result: Awaited<ReturnType<typeof verifyPacket>>): void {
  console.log(`Verdict: ${result.verdict}`);
  console.log(`Document: ${result.manifest.documentName}`);
  console.log(`Completed: ${result.manifest.completedAt}`);
  console.log(`Issuer: ${result.manifest.issuer}`);
  console.log("");
  console.log(`Manifest signature: ${result.checks.manifestSignature}`);
  console.log(
    `Signing key: ${result.checks.signingKeyId.match ? "matched" : "mismatched"} ` +
      `(claimed ${result.checks.signingKeyId.claimed}, expected ${result.checks.signingKeyId.actual})`,
  );
  console.log(
    `Document hash: ${result.checks.documentBinding.status}` +
      (result.checks.documentBinding.computedHash
        ? ` (${result.checks.documentBinding.computedHash})`
        : ""),
  );
  console.log(
    `Bitcoin anchor: ${result.checks.bitcoinAnchor.status} - ${result.checks.bitcoinAnchor.message}`,
  );
}

function printUsage(): void {
  console.log(`Usage:
  pact-verify [options] attestation.json [signed.pdf]

Options:
  --public-key key.pem   Use a custom Ed25519 issuer public key.
  --no-ots              Skip OpenTimestamps receipt verification.
  --json                Print the structured verification result.
  --help                Show this help text.

Exit codes:
  0  verified
  1  invalid
  2  signature/key/hash valid, but Bitcoin anchor is pending or skipped
`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
