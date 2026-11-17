export const SIGNATURE_ALGORITHMS = new Set([
  "ECDSA-SHA256",
  "RSA-PSS-SHA256",
  "RSA-PKCS1V15-SHA256",
  "ED25519",
]);

export function isValidMessageId(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value.trim());
}

export function isValidSha256(value) {
  return typeof value === "string" && /^[a-fA-F0-9]{64}$/.test(value.trim());
}

export function isValidBase64(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 16384) {
    return false;
  }

  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length % 4 !== 0) {
    return false;
  }

  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)
    && Buffer.from(normalized, "base64").length > 0;
}

export function validateRecordMessage(body) {
  const errors = [];

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return ["Request body must be a JSON object."];
  }

  if (!isValidMessageId(body.messageId)) {
    errors.push("messageId must be 1-128 letters, numbers, dots, underscores, or hyphens.");
  }
  if (typeof body.receiver !== "string" || body.receiver.trim().length === 0 || body.receiver.length > 256) {
    errors.push("receiver is required and must be at most 256 characters.");
  }
  if (!isValidSha256(body.messageHash)) {
    errors.push("messageHash must be a 64-character SHA-256 hexadecimal digest.");
  }
  if (!isValidBase64(body.signature)) {
    errors.push("signature must be valid Base64 data.");
  }
  if (typeof body.signatureAlgorithm !== "string"
      || !SIGNATURE_ALGORITHMS.has(body.signatureAlgorithm.trim().toUpperCase())) {
    errors.push("signatureAlgorithm is not supported.");
  }

  return errors;
}
