import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { connectFabric } from "./src/fabric.js";
import {
  validateRecordMessage,
  validateSigningKeyChallenge,
  validateSigningKeyRegistration,
} from "./src/validation.js";

const app = express();
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const allowedOrigin = process.env.CORS_ORIGIN || "http://localhost:5173";

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: allowedOrigin }));
app.use(express.json({ limit: "16kb", strict: true }));

let fabric;

function decodeResult(result) {
  const text = Buffer.from(result).toString("utf8");
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function getContract() {
  if (!fabric) throw new Error("Fabric Gateway is not connected.");
  return fabric.contract;
}

app.get("/health", (_request, response) => {
  response.json({
    status: fabric ? "ok" : "disconnected",
    service: "blocksecure-api",
    channel: process.env.FABRIC_CHANNEL || "mychannel",
    chaincode: process.env.FABRIC_CHAINCODE || "blocksecure",
  });
});


// Prepare a proof-of-possession challenge bound to the caller's Fabric identity.
app.post("/api/signing-key/challenge", async (request, response) => {
  const errors = validateSigningKeyChallenge(request.body);
  if (errors.length) {
    return response.status(400).json({ error: "Invalid request", details: errors });
  }
  try {
    const challenge = await getContract().evaluateTransaction(
      "GetSigningKeyChallenge",
      request.body.publicKeyPem,
      request.body.signatureAlgorithm.trim().toUpperCase(),
    );
    return response.json({ challenge: Buffer.from(challenge).toString("utf8") });
  } catch (error) {
    console.error("Signing-key challenge failed:", String(error?.message || ""));
    return response.status(502).json({ error: "Unable to create a signing-key challenge." });
  }
});

// Register the caller's application key after its owner signs the identity-bound challenge.
app.post("/api/signing-key", async (request, response) => {
  const errors = validateSigningKeyRegistration(request.body);
  if (errors.length) {
    return response.status(400).json({ error: "Invalid request", details: errors });
  }
  const { publicKeyPem, signatureAlgorithm, proofSignature } = request.body;
  try {
    await getContract().submitTransaction(
      "RegisterSigningKey",
      publicKeyPem,
      signatureAlgorithm.trim().toUpperCase(),
      proofSignature.trim(),
    );
    return response.status(201).json({ message: "Signing key registered to the authenticated Fabric identity." });
  } catch (error) {
    const detail = String(error?.message || "");
    if (detail.includes("already registered")) {
      return response.status(409).json({ error: "A signing key is already registered for this Fabric identity." });
    }
    console.error("RegisterSigningKey transaction failed:", detail);
    return response.status(502).json({ error: "Signing-key registration failed." });
  }
});

app.get("/api/signing-key", async (_request, response) => {
  try {
    const result = await getContract().evaluateTransaction("GetSigningKey");
    return response.json(decodeResult(result));
  } catch (error) {
    const detail = String(error?.message || "");
    if (detail.includes("no signing key is registered")) {
      return response.status(404).json({ error: "No signing key is registered for this Fabric identity." });
    }
    console.error("GetSigningKey query failed:", detail);
    return response.status(502).json({ error: "Unable to read the registered signing key." });
  }
});

// Accepts only digest/signature metadata. Message plaintext is never sent to the ledger.
app.post("/api/messages", async (request, response) => {
  const errors = validateRecordMessage(request.body);
  if (errors.length) {
    return response.status(400).json({ error: "Invalid request", details: errors });
  }

  const { messageId, receiver, messageHash, signature } = request.body;
  try {
    await getContract().submitTransaction(
      "RecordMessage",
      messageId.trim(),
      receiver.trim(),
      messageHash.trim().toLowerCase(),
      signature.trim(),
    );

    return response.status(201).json({
      message: "Signed message metadata committed to the BlockSecure ledger.",
      messageId: messageId.trim(),
    });
  } catch (error) {
    const detail = String(error?.message || "");
    if (detail.includes("already exists")) {
      return response.status(409).json({ error: "A message with this messageId already exists." });
    }
    console.error("RecordMessage transaction failed:", detail);
    return response.status(502).json({ error: "The blockchain transaction failed." });
  }
});

app.get("/api/messages", async (request, response) => {
  const sender = typeof request.query.sender === "string" ? request.query.sender.trim() : "";
  const receiver = typeof request.query.receiver === "string" ? request.query.receiver.trim() : "";

  if (sender && receiver) {
    return response.status(400).json({ error: "Filter by sender or receiver, not both." });
  }

  try {
    let result;
    if (sender) {
      result = await getContract().evaluateTransaction("GetMessagesBySender", sender);
    } else if (receiver) {
      result = await getContract().evaluateTransaction("GetMessagesByReceiver", receiver);
    } else {
      result = await getContract().evaluateTransaction("GetAllMessages");
    }
    return response.json(decodeResult(result) ?? []);
  } catch (error) {
    console.error("Message query failed:", String(error?.message || ""));
    return response.status(502).json({ error: "Unable to query message records from the ledger." });
  }
});

app.get("/api/messages/:messageId", async (request, response) => {
  try {
    const result = await getContract().evaluateTransaction("ReadMessage", request.params.messageId);
    return response.json(decodeResult(result));
  } catch (error) {
    const detail = String(error?.message || "");
    if (detail.includes("does not exist")) {
      return response.status(404).json({ error: "Message record not found." });
    }
    console.error("ReadMessage query failed:", detail);
    return response.status(502).json({ error: "Unable to read the message record." });
  }
});

app.get("/api/messages/:messageId/verify", async (request, response) => {
  const submittedHash = request.query.hash;
  if (typeof submittedHash !== "string" || !/^[a-fA-F0-9]{64}$/.test(submittedHash)) {
    return response.status(400).json({ error: "Supply hash as a 64-character SHA-256 hex digest." });
  }

  try {
    const result = await getContract().evaluateTransaction(
      "VerifyMessageHash",
      request.params.messageId,
      submittedHash.toLowerCase(),
    );
    return response.json({ messageId: request.params.messageId, valid: decodeResult(result) === true });
  } catch (error) {
    const detail = String(error?.message || "");
    if (detail.includes("does not exist")) {
      return response.status(404).json({ error: "Message record not found." });
    }
    console.error("VerifyMessageHash query failed:", detail);
    return response.status(502).json({ error: "Unable to verify the message hash." });
  }
});

app.use((error, _request, response, _next) => {
  if (error?.type === "entity.parse.failed") {
    return response.status(400).json({ error: "Request body contains invalid JSON." });
  }
  if (error?.type === "entity.too.large") {
    return response.status(413).json({ error: "Request body is too large." });
  }
  console.error("Unhandled API error:", String(error?.message || error));
  return response.status(500).json({ error: "Internal server error." });
});

let server;
try {
  fabric = connectFabric();
  server = app.listen(port, host, () => {
    console.log(`BlockSecure API listening on http://${host}:${port}`);
  });
} catch (error) {
  console.error("Unable to start BlockSecure API:", error.message);
  process.exitCode = 1;
}

function shutdown() {
  server?.close();
  fabric?.close();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
