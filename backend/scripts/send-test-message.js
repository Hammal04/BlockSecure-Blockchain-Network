import "dotenv/config";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [messageId, receiver, ...messageParts] = process.argv.slice(2);
const message = messageParts.join(" ");

if (!messageId || !receiver || !message) {
  console.error('Usage: node scripts/send-test-message.js <messageId> <receiver> "<message text>"');
  process.exit(1);
}

const privateKeyPath = process.env.FABRIC_IDENTITY_PRIVATE_KEY_PATH;
if (!privateKeyPath) {
  console.error("FABRIC_IDENTITY_PRIVATE_KEY_PATH is missing. Configure backend/.env first.");
  process.exit(1);
}

const privateKey = crypto.createPrivateKey(
  fs.readFileSync(path.resolve(process.cwd(), privateKeyPath)),
);
if (privateKey.asymmetricKeyType !== "ec") {
  console.error("This smoke-test helper expects the default ECDSA Fabric test-network identity.");
  process.exit(1);
}

// The plaintext is hashed and signed locally. Only the digest and signature are sent to the API.
const plaintextBytes = Buffer.from(message, "utf8");
const digest = crypto.createHash("sha256").update(plaintextBytes).digest();
const signature = crypto.sign("sha256", plaintextBytes, privateKey);

const apiBaseUrl = process.env.BLOCKSECURE_API_URL || "http://127.0.0.1:3000";
const response = await fetch(new URL("/api/messages", apiBaseUrl), {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    messageId,
    receiver,
    messageHash: digest.toString("hex"),
    signature: signature.toString("base64"),
    signatureAlgorithm: "ECDSA-SHA256",
  }),
});

const responseBody = await response.text();
console.log(`HTTP ${response.status}`);
console.log(responseBody);

if (!response.ok) {
  process.exitCode = 1;
}
