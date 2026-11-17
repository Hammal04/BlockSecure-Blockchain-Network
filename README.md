# BlockSecure — Blockchain-Based Secure Data Communication Network

**Course:** EE-347 Computer Networks  
**Group:** 13  
**Blockchain platform:** Hyperledger Fabric  
**Chaincode language:** Go  
**Network tooling:** Docker and Docker Compose

## Project overview

BlockSecure is a permissioned-blockchain course project. This repository currently contains the blockchain chaincode work developed and tested on a local Hyperledger Fabric test network.

> **Scope note:** The current chaincode is the Hyperledger Fabric Asset Transfer sample copied into a separate project folder and deployed under the chaincode name `blocksecure`. It demonstrates Fabric network setup, chaincode lifecycle, ledger reads and writes, and asset operations. It is not yet the project-specific secure-message/hash/signature contract, and backend/API integration is still pending.

## Current implementation

The chaincode currently exposes these functions:

| Function | Purpose |
|---|---|
| `InitLedger` | Creates the sample ledger records |
| `CreateAsset` | Creates an asset |
| `ReadAsset` | Reads an asset by ID |
| `UpdateAsset` | Updates an existing asset |
| `DeleteAsset` | Deletes an asset |
| `AssetExists` | Checks whether an asset exists |
| `TransferAsset` | Changes an asset's owner |
| `GetAllAssets` | Returns all assets |

## Development environment

- Hyperledger Fabric test network
- Two peer organizations: Org1 and Org2
- Channel: `mychannel`
- Chaincode name: `blocksecure`
- Chaincode version: `1.0`
- Go toolchain: `1.25.0`
- Fabric Contract API Go dependency: `v2.2.0`

## Verified work

The following operations were run against the local Fabric test network:

- Chaincode packaged and installed on Org1 and Org2 peers.
- Chaincode definition approved by both organizations and committed to `mychannel`.
- Ledger initialization completed successfully.
- Asset create and read operations succeeded.
- Asset ownership transfer was invoked and the new owner was verified.
- Asset update was invoked and the updated record was verified.
- Asset deletion was invoked; a subsequent read correctly reported that the temporary asset did not exist.
- Go tests and `go build ./...` completed successfully for the copied chaincode module.

These results document local test-network validation; they do not yet demonstrate production deployment or the final secure-communication workflow.

## Repository structure

```text
BlockSecure-Blockchain-Network/
├── .gitignore
├── README.md
└── blocksecure-chaincode/
    ├── assetTransfer.go
    ├── go.mod
    ├── go.sum
    └── chaincode/
        ├── smartcontract.go
        ├── smartcontract_test.go
        └── mocks/
            ├── chaincodestub.go
            ├── statequeryiterator.go
            └── transaction.go
```

Local recovery backups and vendored dependencies are excluded from the repository.

## Planned work

1. Design and implement BlockSecure-specific message metadata and integrity-recording functions.
2. Store message hashes and required metadata on the ledger; keep message contents and private keys off-chain.
3. Define and implement the message-signature verification flow in coordination with the cryptography workstream.
4. Integrate the Fabric Gateway/client with the Node.js backend.
5. Connect backend endpoints to the frontend and validate end-to-end behavior with the team.
6. Add integration tests, screenshots, and project documentation.

## Security notes

- Do not commit private keys, wallet identities, MSP credentials, TLS private keys, certificates, passwords, or `.env` files.
- Do not store plaintext private messages or private keys on the blockchain.
- The local Fabric test-network identities and credentials are for development only.

## Developer

Hammal Baloch

## Status

**Current milestone:** Local Fabric test network setup, chaincode lifecycle deployment, and sample asset CRUD/ownership tests completed.  
**Remaining:** Project-specific secure communication chaincode and backend/frontend integration.
