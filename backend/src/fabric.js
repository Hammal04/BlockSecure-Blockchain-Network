import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import grpc from "@grpc/grpc-js";
import { connect, hash, signers } from "@hyperledger/fabric-gateway";

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function resolveFile(value) {
  return path.resolve(process.cwd(), value);
}

export function connectFabric() {
  const endpoint = requiredEnv("FABRIC_GATEWAY_ENDPOINT");
  const tlsServerName = requiredEnv("FABRIC_TLS_SERVER_NAME");
  const tlsRootCert = fs.readFileSync(resolveFile(requiredEnv("FABRIC_TLS_CERT_PATH")));
  const credentials = fs.readFileSync(resolveFile(requiredEnv("FABRIC_IDENTITY_CERT_PATH")));
  const privateKeyPem = fs.readFileSync(resolveFile(requiredEnv("FABRIC_IDENTITY_PRIVATE_KEY_PATH")));
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signer = signers.newPrivateKeySigner(privateKey);

  const client = new grpc.Client(
    endpoint,
    grpc.credentials.createSsl(tlsRootCert),
    {
      "grpc.ssl_target_name_override": tlsServerName,
      "grpc.default_authority": tlsServerName,
    },
  );

  const gateway = connect({
    client,
    identity: {
      mspId: requiredEnv("FABRIC_MSP_ID"),
      credentials,
    },
    signer,
    hash: hash.sha256,
  });

  const network = gateway.getNetwork(process.env.FABRIC_CHANNEL || "mychannel");
  const contract = network.getContract(process.env.FABRIC_CHAINCODE || "blocksecure");

  return {
    contract,
    close() {
      gateway.close();
      client.close();
    },
  };
}
