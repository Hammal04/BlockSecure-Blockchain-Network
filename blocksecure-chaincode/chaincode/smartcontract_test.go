package chaincode

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/base64"
	"encoding/hex"
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
	certPublicKey any
	certRaw []byte
}

func (i testClientIdentity) GetID() (string, error) { return i.id, nil }
func (i testClientIdentity) GetMSPID() (string, error) { return i.msp, nil }
func (i testClientIdentity) GetAttributeValue(string) (string, bool, error) { return "", false, nil }
func (i testClientIdentity) AssertAttributeValue(string, string) error { return nil }
func (i testClientIdentity) GetX509Certificate() (*x509.Certificate, error) {
	return &x509.Certificate{PublicKey: i.certPublicKey, Raw: i.certRaw}, nil
}

var _ cid.ClientIdentity = testClientIdentity{}

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
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
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

func TestRecordMessageUsesAuthenticatedIdentityAndStoresMetadata(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("This is an example message. Plaintext stays off-chain.")
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	stub := &mocks.ChaincodeStub{}
	stub.GetStateReturns(nil, nil)
	stub.GetTxTimestampReturns(timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)), nil)
	stub.GetTxIDReturns("tx-test-001")

	context := &mocks.TransactionContext{}
	context.GetStubReturns(stub)
	context.GetClientIdentityReturns(testClientIdentity{
		id: "x509::/OU=client/CN=hammal",
		msp: "Org1MSP",
		certPublicKey: &privateKey.PublicKey,
		certRaw: []byte("test certificate bytes"),
	})

	contract := &SmartContract{}
	err = contract.RecordMessage(
		context,
		"msg-001",
		"receiver-01",
		hex.EncodeToString(digest[:]),
		base64.StdEncoding.EncodeToString(signature),
		"ECDSA-SHA256",
	)
	require.NoError(t, err)
	require.Equal(t, 1, stub.PutStateCallCount())

	key, stored := stub.PutStateArgsForCall(0)
	require.Equal(t, "message:msg-001", key)
	var record MessageRecord
	require.NoError(t, json.Unmarshal(stored, &record))
	require.Equal(t, "x509::/OU=client/CN=hammal", record.Sender)
	require.Equal(t, "Org1MSP", record.SenderMSPID)
	require.Equal(t, "receiver-01", record.Receiver)
	require.Equal(t, hex.EncodeToString(digest[:]), record.MessageHash)
	require.Equal(t, "tx-test-001", record.TransactionID)
	require.NotContains(t, string(stored), string(message))
}

func TestRecordMessageRejectsBadSignatureAndDuplicate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("payload"))
	validSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)
	validArgs := []string{"msg-002", "receiver", hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(validSignature), "ECDSA-SHA256"}

	newContext := func(existing []byte) (*mocks.TransactionContext, *mocks.ChaincodeStub) {
		stub := &mocks.ChaincodeStub{}
		stub.GetStateReturns(existing, nil)
		context := &mocks.TransactionContext{}
		context.GetStubReturns(stub)
		context.GetClientIdentityReturns(testClientIdentity{
			id: "x509::/CN=sender", msp: "Org1MSP",
			certPublicKey: &privateKey.PublicKey, certRaw: []byte("cert"),
		})
		return context, stub
	}

	contract := &SmartContract{}
	ctx, stub := newContext(nil)
	badSignature := []byte("bad-signature")
	err = contract.RecordMessage(ctx, validArgs[0], validArgs[1], validArgs[2], base64.StdEncoding.EncodeToString(badSignature), validArgs[4])
	require.Error(t, err)
	require.Equal(t, 0, stub.PutStateCallCount())

	ctx, stub = newContext([]byte("already exists"))
	err = contract.RecordMessage(ctx, validArgs[0], validArgs[1], validArgs[2], validArgs[3], validArgs[4])
	require.EqualError(t, err, "message msg-002 already exists")
	require.Equal(t, 0, stub.PutStateCallCount())
}

func TestRecordMessageRejectsInvalidHashAndTimestampError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ctx := &mocks.TransactionContext{}
	stub := &mocks.ChaincodeStub{}
	ctx.GetStubReturns(stub)
	ctx.GetClientIdentityReturns(testClientIdentity{id: "sender", msp: "Org1MSP", certPublicKey: &privateKey.PublicKey, certRaw: []byte("cert")})

	contract := &SmartContract{}
	err = contract.RecordMessage(ctx, "msg-003", "receiver", "bad-hash", "c2ln", "ECDSA-SHA256")
	require.Error(t, err)

	digest := sha256.Sum256([]byte("payload"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)
	stub.GetStateReturns(nil, nil)
	stub.GetTxTimestampReturns(nil, errors.New("timestamp unavailable"))
	err = contract.RecordMessage(ctx, "msg-003", "receiver", hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(signature), "ECDSA-SHA256")
	require.ErrorContains(t, err, "failed to get transaction timestamp")
}

func TestMessageIDValidation(t *testing.T) {
	require.False(t, messageIDPattern.MatchString("../bad/key"))
	require.True(t, messageIDPattern.MatchString("message_001-v1"))
}

var _ contractapi.TransactionContextInterface = (*mocks.TransactionContext)(nil)
