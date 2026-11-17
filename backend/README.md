# BlockSecure Node.js API

This service connects the BlockSecure Go chaincode to a frontend using the official Hyperledger Fabric Gateway Node client. Gateway transactions are submitted with `submitTransaction` and ledger reads use `evaluateTransaction`. See the [Fabric Gateway Node API](https://hyperledger.github.io/fabric-gateway/main/api/node/) and [Fabric Gateway overview](https://hyperledger-fabric.readthedocs.io/en/latest/gateway.html).

## Requirements

- Node.js 20 or newer
- A running Hyperledger Fabric test network with the `blocksecure` chaincode deployed and committed
- A Fabric X.509 identity and its private key
- The TLS CA certificate for the peer Gateway endpoint

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

Copy the resulting file path into `FABRIC_IDENTITY_PRIVATE_KEY_PATH`. Do not copy certificates or private keys into this repository. Never commit `.env`.

The example config connects to Org1's peer Gateway at `localhost:7051`, using `Org1MSP`, channel `mychannel`, and chaincode `blocksecure`.

## Start

```bash
npm start
```

The API listens on `http://127.0.0.1:3000` by default. Set `HOST=0.0.0.0` only when you deliberately need access from another machine and have secured the service.

## API

### Record a signed message digest

`POST /api/messages`

JSON body:

```json
{
  "messageId": "msg-0001",
  "receiver": "Org2MSP::recipient",
  "messageHash": "64-character SHA-256 hex digest",
  "signature": "Base64-encoded application signature",
  "signatureAlgorithm": "ECDSA-SHA256"
}
```

Supported algorithms: `ECDSA-SHA256`, `RSA-PSS-SHA256`, `RSA-PKCS1V15-SHA256`, `ED25519`.

The signature must be generated over the SHA-256 digest of the original message. For ECDSA and RSA, use SHA-256 as the signing digest. For Ed25519, sign the 32 digest bytes directly.

The chaincode derives the sender from the authenticated Fabric X.509 identity and verifies the signature using that identity's certificate public key. The client-supplied `sender` value is intentionally not accepted. The plaintext message and private key are not sent to the API or stored on the ledger.

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

This starter service uses the single Fabric identity configured in `.env` for all submitted transactions. Therefore records are attributed to that configured Fabric identity. For per-user sender attribution, the authentication layer must map each logged-in application user to their own Fabric enrollment identity and create/use a Gateway connection for that identity. Do not expose an Admin private key to the browser or commit it to source control.

## End-to-end smoke test

After the API is running and `.env` points to the same Org1 identity certificate/private key used by the Gateway, open a second terminal in this directory and run:

```bash
node scripts/send-test-message.js demo-001 "Org2MSP::recipient" "This plaintext is hashed locally and not sent to the API"
```

The helper hashes and signs the supplied message locally, then sends only the digest and signature metadata to `POST /api/messages`. It is intended for a local integration smoke test with the default ECDSA Fabric test-network identity. Use a new `messageId` each time because message records are immutable and duplicate IDs are rejected.

You can then inspect the ledger record:

```bash
curl http://127.0.0.1:3000/api/messages/demo-001
```

And verify a supplied digest:

```bash
curl "http://127.0.0.1:3000/api/messages/demo-001/verify?hash=<64-character-sha256-hex>"
```

## Tests

```bash
npm test
```

The included Node tests check API input validation. The Go chaincode tests cover hash parsing, supported signature verification, authenticated sender attribution, and ledger record creation. Run the Go tests from `blocksecure-chaincode` with `go test ./...`.

## Security / deployment notes

- This is a local development integration starter, not a production-ready public API.
- Add application authentication and authorization before exposing it beyond localhost.
- Use HTTPS and secrets management in any shared deployment.
- Keep private message content off-chain; only message hashes and necessary metadata belong in the ledger.
- Ensure the frontend computes the message hash and obtains a valid signature from the same Fabric identity that submits the transaction.
