package chaincode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode/mocks"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testClientIdentity struct {
	id  string
	msp string
}

func (i testClientIdentity) GetID() (string, error) { return i.id, nil }
func (i testClientIdentity) GetMSPID() (string, error) { return i.msp, nil }
func (i testClientIdentity) GetAttributeValue(string) (string, bool, error) { return "", false, nil }
func (i testClientIdentity) AssertAttributeValue(string, string) error { return nil }
func (i testClientIdentity) GetX509Certificate() (*x509.Certificate, error) { return nil, nil }

var _ cid.ClientIdentity = testClientIdentity{}
var _ contractapi.TransactionContextInterface = (*mocks.TransactionContext)(nil)

func makeECDSAKey(t *testing.T) (*ecdsa.PrivateKey, string, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	fingerprint := sha256.Sum256(der)
	return privateKey, publicKeyPEM, fingerprint[:]
}

func makeRegisteredKey(t *testing.T, privateKey *ecdsa.PrivateKey, publicKeyPEM string, sender string, mspID string) *SigningKeyRecord {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	fingerprint := sha256.Sum256(der)
	return &SigningKeyRecord{
		Sender: sender,
		SenderMSPID: mspID,
		PublicKeyPEM: publicKeyPEM,
		PublicKeySHA256: hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm: "ECDSA-SHA256",
		RegisteredAt: "2026-01-02T03:04:05Z",
		TransactionID: "tx-key-001",
	}
}

func TestParseSHA256Hash(t *testing.T) {
	digest := sha256.Sum256([]byte("BlockSecure test"))
	parsed, normalized, err := parseSHA256Hash(hex.EncodeToString(digest[:]))
	require.NoError(t, err)
	require.Equal(t, digest[:], parsed)
	require.Equal(t, hex.EncodeToString(digest[:]), normalized)

	_, _, err = parseSHA256Hash("not-a-hash")
	require.Error(t, err)
}

func TestVerifyPublicKeySignatureECDSA(t *testing.T) {
	privateKey, _, _ := makeECDSAKey(t)
	digest := sha256.Sum256([]byte("signed message"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	require.NoError(t, verifyPublicKeySignature(&privateKey.PublicKey, digest[:], signature, "ECDSA-SHA256"))
	require.Error(t, verifyPublicKeySignature(&privateKey.PublicKey, []byte("wrong digest"), signature, "ECDSA-SHA256"))
	require.Error(t, verifyPublicKeySignature(&privateKey.PublicKey, digest[:], signature, "UNKNOWN"))
}

func TestVerifyPublicKeySignatureEd25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("signed message"))
	signature := ed25519.Sign(privateKey, digest[:])
	require.NoError(t, verifyPublicKeySignature(publicKey, digest[:], signature, "ED25519"))
	require.Error(t, verifyPublicKeySignature(publicKey, []byte("wrong"), signature, "ED25519"))
}

func TestVerifyPublicKeySignatureRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("signed message"))
	pssSignature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	require.NoError(t, verifyPublicKeySignature(&privateKey.PublicKey, digest[:], pssSignature, "RSA-PSS-SHA256"))

	pkcsSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	require.NoError(t, err)
	require.NoError(t, verifyPublicKeySignature(&privateKey.PublicKey, digest[:], pkcsSignature, "RSA-PKCS1V15-SHA256"))
}

func TestGetSigningKeyChallengeAndRegisterSigningKey(t *testing.T) {
	privateKey, publicKeyPEM, fingerprintBytes := makeECDSAKey(t)
	identity := testClientIdentity{id: "x509::/OU=client/CN=hammal", msp: "Org1MSP"}
	fingerprint := hex.EncodeToString(fingerprintBytes)
	challenge := makeSigningKeyChallenge(identity.msp, identity.id, fingerprint, "ECDSA-SHA256")
	challengeDigest := sha256.Sum256([]byte(challenge))
	proof, err := ecdsa.SignASN1(rand.Reader, privateKey, challengeDigest[:])
	require.NoError(t, err)
	proofBase64 := base64.StdEncoding.EncodeToString(proof)

	stub := &mocks.ChaincodeStub{}
	stub.GetStateReturns(nil, nil)
	stub.GetTxTimestampReturns(timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)), nil)
	stub.GetTxIDReturns("tx-key-001")
	ctx := &mocks.TransactionContext{}
	ctx.GetStubReturns(stub)
	ctx.GetClientIdentityReturns(identity)
	contract := &SmartContract{}

	actualChallenge, err := contract.GetSigningKeyChallenge(ctx, publicKeyPEM, "ecdsa-sha256")
	require.NoError(t, err)
	require.Equal(t, challenge, actualChallenge)

	err = contract.RegisterSigningKey(ctx, publicKeyPEM, "ECDSA-SHA256", proofBase64)
	require.NoError(t, err)
	require.Equal(t, 1, stub.PutStateCallCount())

	key, value := stub.PutStateArgsForCall(0)
	require.Equal(t, signingKeyStateKey(identity.msp, identity.id), key)
	var saved SigningKeyRecord
	require.NoError(t, json.Unmarshal(value, &saved))
	require.Equal(t, identity.id, saved.Sender)
	require.Equal(t, identity.msp, saved.SenderMSPID)
	require.Equal(t, fingerprint, saved.PublicKeySHA256)
	require.Equal(t, "ECDSA-SHA256", saved.SignatureAlgorithm)
}

func TestRegisterSigningKeyRejectsBadProofDuplicateAndWeakRSA(t *testing.T) {
	privateKey, publicKeyPEM, fingerprintBytes := makeECDSAKey(t)
	identity := testClientIdentity{id: "sender-id", msp: "Org1MSP"}
	fingerprint := hex.EncodeToString(fingerprintBytes)
	challenge := makeSigningKeyChallenge(identity.msp, identity.id, fingerprint, "ECDSA-SHA256")
	digest := sha256.Sum256([]byte(challenge))
	proof, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	newContext := func(existing []byte) (*mocks.TransactionContext, *mocks.ChaincodeStub) {
		stub := &mocks.ChaincodeStub{}
		stub.GetStateReturns(existing, nil)
		ctx := &mocks.TransactionContext{}
		ctx.GetStubReturns(stub)
		ctx.GetClientIdentityReturns(identity)
		return ctx, stub
	}
	contract := &SmartContract{}

	ctx, stub := newContext(nil)
	err = contract.RegisterSigningKey(ctx, publicKeyPEM, "ECDSA-SHA256", base64.StdEncoding.EncodeToString([]byte("bad proof")))
	require.Error(t, err)
	require.Equal(t, 0, stub.PutStateCallCount())

	ctx, stub = newContext([]byte("already registered"))
	err = contract.RegisterSigningKey(ctx, publicKeyPEM, "ECDSA-SHA256", base64.StdEncoding.EncodeToString(proof))
	require.EqualError(t, err, "a signing key is already registered for this Fabric identity")
	require.Equal(t, 0, stub.PutStateCallCount())

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	weakDER, err := x509.MarshalPKIXPublicKey(&weakRSA.PublicKey)
	require.NoError(t, err)
	weakPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakDER}))
	_, _, _, err = parseAndValidatePublicKey(weakPEM, "RSA-PSS-SHA256")
	require.Error(t, err)
}

func TestRecordMessageUsesRegisteredSigningKeyAndStoresNoPlaintext(t *testing.T) {
	privateKey, publicKeyPEM, _ := makeECDSAKey(t)
	identity := testClientIdentity{id: "x509::/OU=client/CN=hammal", msp: "Org1MSP"}
	registeredKey := makeRegisteredKey(t, privateKey, publicKeyPEM, identity.id, identity.msp)
	registeredJSON, err := json.Marshal(registeredKey)
	require.NoError(t, err)

	plaintext := []byte("This plaintext remains off-chain.")
	digest := sha256.Sum256(plaintext)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	stub := &mocks.ChaincodeStub{}
	stub.GetStateReturnsOnCall(0, registeredJSON, nil)
	stub.GetStateReturnsOnCall(1, nil, nil)
	stub.GetTxTimestampReturns(timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)), nil)
	stub.GetTxIDReturns("tx-message-001")
	ctx := &mocks.TransactionContext{}
	ctx.GetStubReturns(stub)
	ctx.GetClientIdentityReturns(identity)

	err = (&SmartContract{}).RecordMessage(
		ctx,
		"msg-001",
		"Org2MSP::recipient",
		hex.EncodeToString(digest[:]),
		base64.StdEncoding.EncodeToString(signature),
	)
	require.NoError(t, err)
	require.Equal(t, 1, stub.PutStateCallCount())

	key, stored := stub.PutStateArgsForCall(0)
	require.Equal(t, "message:msg-001", key)
	var record MessageRecord
	require.NoError(t, json.Unmarshal(stored, &record))
	require.Equal(t, identity.id, record.Sender)
	require.Equal(t, identity.msp, record.SenderMSPID)
	require.Equal(t, "Org2MSP::recipient", record.Receiver)
	require.Equal(t, hex.EncodeToString(digest[:]), record.MessageHash)
	require.Equal(t, registeredKey.PublicKeySHA256, record.SignerKeyFingerprint)
	require.Equal(t, "tx-message-001", record.TransactionID)
	require.NotContains(t, string(stored), string(plaintext))
}

func TestRecordMessageRejectsInvalidSignatureDuplicateAndMissingKey(t *testing.T) {
	privateKey, publicKeyPEM, _ := makeECDSAKey(t)
	identity := testClientIdentity{id: "sender-id", msp: "Org1MSP"}
	registeredKey := makeRegisteredKey(t, privateKey, publicKeyPEM, identity.id, identity.msp)
	registeredJSON, err := json.Marshal(registeredKey)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("payload"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	newContext := func(keyValue []byte, messageValue []byte) (*mocks.TransactionContext, *mocks.ChaincodeStub) {
		stub := &mocks.ChaincodeStub{}
		stub.GetStateReturnsOnCall(0, keyValue, nil)
		stub.GetStateReturnsOnCall(1, messageValue, nil)
		ctx := &mocks.TransactionContext{}
		ctx.GetStubReturns(stub)
		ctx.GetClientIdentityReturns(identity)
		return ctx, stub
	}
	contract := &SmartContract{}

	ctx, stub := newContext(registeredJSON, nil)
	err = contract.RecordMessage(ctx, "msg-002", "receiver", hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString([]byte("bad")))
	require.Error(t, err)
	require.Equal(t, 0, stub.PutStateCallCount())

	ctx, stub = newContext(registeredJSON, []byte("already exists"))
	err = contract.RecordMessage(ctx, "msg-002", "receiver", hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(signature))
	require.EqualError(t, err, "message msg-002 already exists")
	require.Equal(t, 0, stub.PutStateCallCount())

	ctx, stub = newContext(nil, nil)
	err = contract.RecordMessage(ctx, "msg-003", "receiver", hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(signature))
	require.EqualError(t, err, "no signing key is registered for this Fabric identity")
	require.Equal(t, 0, stub.PutStateCallCount())
}

func TestReadMessageVerifyHashAndMessageIDValidation(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	record := MessageRecord{MessageID: "msg-004", MessageHash: hex.EncodeToString(digest[:])}
	recordJSON, err := json.Marshal(record)
	require.NoError(t, err)

	stub := &mocks.ChaincodeStub{}
	stub.GetStateReturns(recordJSON, nil)
	ctx := &mocks.TransactionContext{}
	ctx.GetStubReturns(stub)
	contract := &SmartContract{}

	read, err := contract.ReadMessage(ctx, "msg-004")
	require.NoError(t, err)
	require.Equal(t, record.MessageID, read.MessageID)

	valid, err := contract.VerifyMessageHash(ctx, "msg-004", strings.ToUpper(record.MessageHash))
	require.NoError(t, err)
	require.True(t, valid)

	wrongDigest := sha256.Sum256([]byte("different"))
	valid, err = contract.VerifyMessageHash(ctx, "msg-004", hex.EncodeToString(wrongDigest[:]))
	require.NoError(t, err)
	require.False(t, valid)

	require.False(t, messageIDPattern.MatchString("../bad/key"))
	require.True(t, messageIDPattern.MatchString("message_001-v1"))

	stub.GetStateReturns(nil, errors.New("ledger unavailable"))
	_, err = contract.ReadMessage(ctx, "msg-004")
	require.Error(t, err)
}
