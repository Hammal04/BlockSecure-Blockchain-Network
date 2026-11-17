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

const privateKeyPath = process.env.BLOCKSECURE_SIGNING_PRIVATE_KEY_PATH
  || process.env.FABRIC_IDENTITY_PRIVATE_KEY_PATH;
if (!privateKeyPath) {
  console.error("Set BLOCKSECURE_SIGNING_PRIVATE_KEY_PATH or FABRIC_IDENTITY_PRIVATE_KEY_PATH in backend/.env.");
  process.exit(1);
}

const privateKey = crypto.createPrivateKey(
  fs.readFileSync(path.resolve(process.cwd(), privateKeyPath)),
);
const algorithm = (process.env.BLOCKSECURE_SIGNING_ALGORITHM || "ECDSA-SHA256").toUpperCase();

function signBytes(bytes) {
  switch (algorithm) {
    case "ECDSA-SHA256":
      if (privateKey.asymmetricKeyType !== "ec") throw new Error("ECDSA-SHA256 requires an EC private key.");
      return crypto.sign("sha256", bytes, privateKey);
    case "RSA-PSS-SHA256":
      if (privateKey.asymmetricKeyType !== "rsa" && privateKey.asymmetricKeyType !== "rsa-pss") {
        throw new Error("RSA-PSS-SHA256 requires an RSA private key.");
      }
      return crypto.sign("sha256", bytes, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      });
    case "RSA-PKCS1V15-SHA256":
      if (privateKey.asymmetricKeyType !== "rsa") throw new Error("RSA-PKCS1V15-SHA256 requires an RSA private key.");
      return crypto.sign("sha256", bytes, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      });
    case "ED25519": {
      if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("ED25519 requires an Ed25519 private key.");
      const digest = crypto.createHash("sha256").update(bytes).digest();
      return crypto.sign(null, digest, privateKey);
    }
    default:
      throw new Error(`Unsupported signing algorithm: ${algorithm}`);
  }
}

const apiBaseUrl = process.env.BLOCKSECURE_API_URL || "http://127.0.0.1:3000";
async function api(pathname, options) {
  const response = await fetch(new URL(pathname, apiBaseUrl), options);
  const bodyText = await response.text();
  let body;
  try { body = bodyText ? JSON.parse(bodyText) : null; } catch { body = bodyText; }
  return { response, body };
}

const publicKey = crypto.createPublicKey(privateKey);
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const publicKeyDER = publicKey.export({ format: "der", type: "spki" });
const publicKeyFingerprint = crypto.createHash("sha256").update(publicKeyDER).digest("hex");

// Register the app key once, bound to the authenticated Fabric identity.
const currentKey = await api("/api/signing-key", { method: "GET" });
if (currentKey.response.ok) {
  if (currentKey.body.publicKeySha256 !== publicKeyFingerprint) {
    throw new Error("A different signing key is already registered for this Fabric identity. Key rotation is not enabled.");
  }
  console.log("Signing key already registered for this Fabric identity.");
} else if (currentKey.response.status === 404) {
  const challengeResult = await api("/api/signing-key/challenge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKeyPem, signatureAlgorithm: algorithm }),
  });
  if (!challengeResult.response.ok) {
    throw new Error(`Unable to obtain signing-key challenge: ${JSON.stringify(challengeResult.body)}`);
  }

  const proofSignature = signBytes(Buffer.from(challengeResult.body.challenge, "utf8")).toString("base64");
  const registration = await api("/api/signing-key", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKeyPem, signatureAlgorithm: algorithm, proofSignature }),
  });
  if (!registration.response.ok) {
    throw new Error(`Signing-key registration failed: ${JSON.stringify(registration.body)}`);
  }
  console.log("Signing key registered to the authenticated Fabric identity.");
} else {
  throw new Error(`Unable to check registered signing key: ${JSON.stringify(currentKey.body)}`);
}

// The message plaintext is hashed and signed locally. Only digest and signature metadata are sent.
const plaintextBytes = Buffer.from(message, "utf8");
const digest = crypto.createHash("sha256").update(plaintextBytes).digest();
const signature = signBytes(plaintextBytes);
const submission = await api("/api/messages", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    messageId,
    receiver,
    messageHash: digest.toString("hex"),
    signature: signature.toString("base64"),
  }),
});

console.log(`HTTP ${submission.response.status}`);
console.log(submission.body);

if (!submission.response.ok) {
  process.exitCode = 1;
}
