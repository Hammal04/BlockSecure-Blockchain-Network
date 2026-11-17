# BlockSecure Node.js API

This service connects the BlockSecure Go chaincode to a frontend using the official Hyperledger Fabric Gateway Node client. Gateway writes use `submitTransaction`; ledger reads use `evaluateTransaction`. See the [Fabric Gateway Node API](https://hyperledger.github.io/fabric-gateway/main/api/node/) and [Fabric Gateway overview](https://hyperledger-fabric.readthedocs.io/en/latest/gateway.html).

## Requirements

- Node.js 20 or newer
- A running Hyperledger Fabric test network with the current `blocksecure` message-ledger chaincode deployed and committed
- A Fabric X.509 identity and private key for the Gateway connection
- The TLS CA certificate for the peer Gateway endpoint
- An application signing key (ECDSA, RSA, or Ed25519). It can be separate from the Fabric enrollment key.

## Install

From this directory:

```bash
npm install
cp .env.example .env
```

Edit `.env` and set the exact paths for the local test-network certificates and identity.

For the sample Org1 User1 identity, locate its private key with:

```bash
find ../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore -type f
```

Copy the resulting file path into `FABRIC_IDENTITY_PRIVATE_KEY_PATH`. By default, the smoke-test helper reuses that private key as the application signing key. To use the cryptography workstream's separate key, set `BLOCKSECURE_SIGNING_PRIVATE_KEY_PATH` to its local path and set `BLOCKSECURE_SIGNING_ALGORITHM` to the matching supported algorithm. Do not copy certificates or private keys into this repository. Never commit `.env`.

The example config connects to Org1's peer Gateway at `localhost:7051`, using `Org1MSP`, channel `mychannel`, and chaincode `blocksecure`.

## Start

```bash
npm start
```

The API listens on `http://127.0.0.1:3000` by default. Set `HOST=0.0.0.0` only when you deliberately need access from another machine and have secured the service.

## API

### Get an identity-bound signing-key challenge

`POST /api/signing-key/challenge`

Request body:

```json
{
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
  "signatureAlgorithm": "ECDSA-SHA256"
}
```

The chaincode creates a challenge bound to the authenticated submitter's Fabric ID, MSP, key fingerprint, and selected algorithm.

### Register the signing key

`POST /api/signing-key`

Request body:

```json
{
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",
  "signatureAlgorithm": "ECDSA-SHA256",
  "proofSignature": "Base64 signature over SHA-256(challenge)"
}
```

The caller must sign the challenge with the private key corresponding to `publicKeyPem`. The chaincode verifies proof of possession and permanently binds that application public key to the authenticated Fabric identity. Only one key can currently be registered per Fabric identity; key rotation is not implemented.

### Read the caller's registered signing key

`GET /api/signing-key`

### Record a signed message digest

`POST /api/messages`

Request body:

```json
{
  "messageId": "msg-0001",
  "receiver": "Org2MSP::recipient",
  "messageHash": "64-character SHA-256 hex digest",
  "signature": "Base64 signature over SHA-256(message)"
}
```

Supported algorithms are selected at key registration: `ECDSA-SHA256`, `RSA-PSS-SHA256`, `RSA-PKCS1V15-SHA256`, and `ED25519`. For ECDSA and RSA, sign the original message with SHA-256; for Ed25519, sign the 32 digest bytes. The chaincode looks up the key registered to the authenticated Fabric identity and verifies each message signature against it. The sender is derived from Fabric identity; clients cannot submit an arbitrary sender string.

The plaintext message is not sent to the API or stored on the ledger. The client/cryptography component computes the digest and signature locally and sends only the digest and signature metadata.

### Read one record

`GET /api/messages/:messageId`

### List records

- `GET /api/messages`
- `GET /api/messages?sender=<Fabric-client-identity-ID>`
- `GET /api/messages?receiver=<receiver-id>`

### Verify a digest against the ledger

`GET /api/messages/:messageId/verify?hash=<sha256-hex>`

### Health

`GET /health`

## Important identity model

This starter service uses the single Fabric identity configured in `.env` for all submitted transactions. Therefore the chaincode attributes registrations and messages to that configured Fabric identity. The registered application signing key may be separate, and its ownership is proven by signing the identity-bound challenge. For per-user sender attribution, add application authentication and map each logged-in user to their own Fabric enrollment identity/Gateway session. Do not expose an Admin private key to the browser or commit it to source control.

## End-to-end smoke test

After the current message-ledger chaincode is deployed and the API is running, open a second terminal in this directory and run:

```bash
node scripts/send-test-message.js demo-001 "Org2MSP::recipient" "This plaintext is hashed locally and not sent to the API"
```

The helper performs these steps locally:
1. Loads the configured application private key.
2. Requests a signing-key challenge from the API.
3. Registers its public key once by submitting a proof-of-possession signature.
4. Hashes and signs the example message locally.
5. Sends only the digest and signature to `POST /api/messages`.

Use a new `messageId` each time because message records are immutable and duplicate IDs are rejected.

You can then inspect the ledger record:

```bash
curl http://127.0.0.1:3000/api/messages/demo-001
```

And verify a digest:

```bash
curl "http://127.0.0.1:3000/api/messages/demo-001/verify?hash=<64-character-sha256-hex>"
```

## Tests

```bash
npm test
```

The Node tests check API input validation. The Go tests cover hash parsing, supported signatures, signing-key registration proof, identity binding, message recording, and duplicate rejection. Run Go tests from `blocksecure-chaincode` with `go test ./...`.

## Security / deployment notes

- This is a local development integration starter, not a production-ready public API.
- Add application authentication and authorization before exposing it beyond localhost.
- Use HTTPS and secrets management in any shared deployment.
- Keep plaintext message content off-chain; only message hashes and necessary metadata belong in the ledger.
- A signing key is bound to a Fabric identity; use per-user Gateway sessions when multiple senders must be represented.
- Key rotation, revocation, access-controlled message listing, and persistent off-chain message delivery are future work.
