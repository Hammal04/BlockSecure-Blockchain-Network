# BlockSecure — Blockchain-Based Secure Data Communication Network

**Course:** EE-347 Computer Networks  
**Group:** 13  
**Blockchain:** Hyperledger Fabric  
**Chaincode:** Go  
**Backend:** Node.js REST API using Fabric Gateway

## Project overview

BlockSecure is a permissioned-blockchain project for recording and validating secure-message integrity metadata. The blockchain stores message hashes, the authenticated sender identity, receiver metadata, a digital signature, and transaction metadata. **Message plaintext and private keys remain off-chain.**

This repository contains the Go smart contract and a Node.js API starter that connects to the Fabric Gateway.

## Architecture

1. The client/cryptography component creates a SHA-256 digest of a message and signs that digest.
2. The Node.js API receives only the digest and signature metadata; it does not accept or persist plaintext message content.
3. The API submits the transaction through the Hyperledger Fabric Gateway.
4. The Go chaincode derives the sender from the authenticated Fabric X.509 identity and verifies the signature using that identity certificate's public key.
5. The chaincode records the signed digest and metadata on `mychannel`.
6. The API can retrieve message records and compare a submitted digest with the on-chain digest.

The application signing key can differ from the Fabric enrollment key, but it must be registered with a proof-of-possession challenge under the authenticated Fabric identity. The included API starter uses one Fabric identity from its local `.env` configuration. For per-user attribution, the backend must use a separate authenticated Fabric identity/Gateway session for each user. Key rotation is not implemented yet.

## Smart contract transactions

| Function | Purpose |
|---|---|
| `GetSigningKeyChallenge` | Create a proof-of-possession challenge bound to the caller Fabric identity |
| `RegisterSigningKey` | Verify key ownership and bind one app public key to the caller Fabric identity |
| `GetSigningKey` | Read the signing key registered to the caller |
| `RecordMessage` | Verify the registered key signature and store message metadata |
| `ReadMessage` | Read a message record by ID |
| `MessageExists` | Check whether a message ID is already recorded |
| `VerifyMessageHash` | Compare a supplied SHA-256 digest with the ledger record |
| `GetAllMessages` | Return all recorded messages |
| `GetMessagesBySender` | List records for a Fabric client identity |
| `GetMessagesByReceiver` | List records for a receiver |

Supported application-signature algorithms are `ECDSA-SHA256`, `RSA-PSS-SHA256`, `RSA-PKCS1V15-SHA256`, and `ED25519`. The signature input is Base64 and the message hash is a 64-character SHA-256 hexadecimal digest. The Fabric test-network identity is normally ECDSA; other algorithms require a matching supported X.509 identity key.

## Node.js API

The `backend/` directory connects to Fabric using the official [Hyperledger Fabric Gateway Node API](https://hyperledger.github.io/fabric-gateway/main/api/node/).

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | API health and configured channel/chaincode |
| POST | `/api/signing-key/challenge` | Create a key-registration challenge |
| POST | `/api/signing-key` | Register a public key with proof of possession |
| GET | `/api/signing-key` | Read the caller's registered key |
| POST | `/api/messages` | Submit a signed message digest |
| GET | `/api/messages` | List all message records |
| GET | `/api/messages?sender=<id>` | Filter by sender |
| GET | `/api/messages?receiver=<id>` | Filter by receiver |
| GET | `/api/messages/:messageId` | Read a message record |
| GET | `/api/messages/:messageId/verify?hash=<sha256>` | Verify a digest against the ledger |

See [backend/README.md](backend/README.md) for installation, environment configuration, API request format, and local startup instructions.

## Repository structure

```text
BlockSecure-Blockchain-Network/
├── .gitignore
├── README.md
├── blocksecure-chaincode/
│   ├── assetTransfer.go
│   ├── go.mod
│   ├── go.sum
│   └── chaincode/
│       ├── smartcontract.go
│       ├── smartcontract_test.go
│       └── mocks/
└── backend/
    ├── .env.example
    ├── package.json
    ├── server.js
    ├── README.md
    ├── scripts/
    │   └── send-test-message.js
    └── src/
        ├── fabric.js
        ├── validation.js
        └── validation.test.js
```

Private environment files, Fabric credentials, backups, and vendored dependencies are excluded from version control.

## Deploy the updated signed-message chaincode

The earlier local Fabric test-network session deployed the sample asset-transfer contract as version `1.0`, sequence `1`. The signed-message contract in this repository is a new chaincode definition. After pulling this repository, deploy it as a new version and sequence; do not try to invoke the new message transactions against the old package.

From the local test-network directory, after the existing network/channel are running:

```bash
cd ~/BlockSecure/fabric-samples/test-network
source scripts/envVar.sh
./network.sh deployCC -ccn blocksecure -ccp ../../BlockSecure-GitHub/blocksecure-chaincode -ccl go -ccv 2.0 -ccs 2
```

This command assumes the repository clone is at `~/BlockSecure/BlockSecure-GitHub`. Adjust the chaincode path if your clone is elsewhere. Confirm the output says the new chaincode definition is committed on `mychannel` before starting the backend.

## Local development requirements

- Hyperledger Fabric v2.4 or later with the peer Gateway service enabled
- Docker and Docker Compose
- Go 1.25 or newer for the chaincode
- Node.js 20 or newer for the API

The earlier local test-network work verified the Fabric network lifecycle and demonstrated message-independent asset CRUD operations. The message-ledger contract and REST API in this repository are the next implementation stage and **must be tested and redeployed locally before being described as operational**.

## Continuous integration

GitHub Actions runs the Go chaincode tests/build and the Node API validation tests on pushes and pull requests to `main`. See the [Actions workflow](.github/workflows/ci.yml).

## Local checks

Run Go tests/build from `blocksecure-chaincode/`:

```bash
go test ./...
go build ./...
```

Run the API validation tests from `backend/`:

```bash
npm install
npm test
```

## Security notes

- Never commit private keys, wallet identities, MSP private material, TLS private keys, passwords, or real `.env` files.
- Do not send plaintext messages or private keys to the chaincode or store them on the ledger.
- Chaincode validates the application signature against the authenticated submitter's Fabric X.509 certificate. The submitting identity and message-signing key must therefore match.
- The backend starter is intended for local development. Add user authentication, per-user Fabric identity handling, authorization, HTTPS, and secrets management before exposing it to a shared or production environment.

## Developer

Hammal Baloch
