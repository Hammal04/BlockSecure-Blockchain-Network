package chaincode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

const (
	messageKeyPrefix     = "message:"
	signingKeyKeyPrefix  = "signing-key:"
	signingKeyChallengeV1 = "BlockSecure signing-key registration v1"
)

var messageIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SmartContract exposes signed-message integrity transactions.
type SmartContract struct {
	contractapi.Contract
}

// SigningKeyRecord binds an application signing key to the authenticated
// Fabric identity that registered it.
type SigningKeyRecord struct {
	Sender             string `json:"sender"`
	SenderMSPID        string `json:"senderMspId"`
	PublicKeyPEM       string `json:"publicKeyPem"`
	PublicKeySHA256    string `json:"publicKeySha256"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	RegisteredAt       string `json:"registeredAt"`
	TransactionID      string `json:"transactionId"`
}

// MessageRecord is the immutable on-chain message-integrity record.
// No message plaintext or private key is stored here.
type MessageRecord struct {
	MessageID             string `json:"messageId"`
	Sender                string `json:"sender"`
	SenderMSPID           string `json:"senderMspId"`
	Receiver              string `json:"receiver"`
	MessageHash           string `json:"messageHash"`
	Signature             string `json:"signature"`
	SignatureAlgorithm    string `json:"signatureAlgorithm"`
	SignerKeyFingerprint  string `json:"signerKeyFingerprint"`
	CreatedAt             string `json:"createdAt"`
	TransactionID         string `json:"transactionId"`
}

// GetSigningKeyChallenge creates the challenge that a caller must sign to
// prove possession of a public key before registering it to their Fabric ID.
// Args: publicKeyPEM, signatureAlgorithm.
func (s *SmartContract) GetSigningKeyChallenge(
	ctx contractapi.TransactionContextInterface,
	publicKeyPEM string,
	signatureAlgorithm string,
) (string, error) {
	senderID, mspID, err := getSubmittingIdentity(ctx)
	if err != nil {
		return "", err
	}
	_, fingerprint, algorithm, err := parseAndValidatePublicKey(publicKeyPEM, signatureAlgorithm)
	if err != nil {
		return "", err
	}
	return makeSigningKeyChallenge(mspID, senderID, fingerprint, algorithm), nil
}

// RegisterSigningKey permanently binds an application public key to the
// authenticated Fabric identity. proofSignature must be Base64 and sign the
// SHA-256 digest of the challenge returned by GetSigningKeyChallenge.
// A second key registration is rejected; key rotation needs an explicit
// future transaction with proof from the currently registered key.
func (s *SmartContract) RegisterSigningKey(
	ctx contractapi.TransactionContextInterface,
	publicKeyPEM string,
	signatureAlgorithm string,
	proofSignatureBase64 string,
) error {
	senderID, mspID, err := getSubmittingIdentity(ctx)
	if err != nil {
		return err
	}
	publicKey, fingerprint, algorithm, err := parseAndValidatePublicKey(publicKeyPEM, signatureAlgorithm)
	if err != nil {
		return err
	}
	proofSignature, err := decodeBase64Signature(proofSignatureBase64)
	if err != nil {
		return err
	}
	challenge := makeSigningKeyChallenge(mspID, senderID, fingerprint, algorithm)
	challengeDigest := sha256.Sum256([]byte(challenge))
	if err := verifyPublicKeySignature(publicKey, challengeDigest[:], proofSignature, algorithm); err != nil {
		return fmt.Errorf("signing-key proof failed: %w", err)
	}

	stateKey := signingKeyStateKey(mspID, senderID)
	existing, err := ctx.GetStub().GetState(stateKey)
	if err != nil {
		return fmt.Errorf("failed to check signing-key registration: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("a signing key is already registered for this Fabric identity")
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	if txTimestamp == nil {
		return fmt.Errorf("transaction timestamp is unavailable")
	}

	record := SigningKeyRecord{
		Sender:             senderID,
		SenderMSPID:        mspID,
		PublicKeyPEM:       strings.TrimSpace(publicKeyPEM),
		PublicKeySHA256:    fingerprint,
		SignatureAlgorithm: algorithm,
		RegisteredAt:       time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano),
		TransactionID:      ctx.GetStub().GetTxID(),
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to encode signing-key record: %w", err)
	}
	if err := ctx.GetStub().PutState(stateKey, recordJSON); err != nil {
		return fmt.Errorf("failed to store signing key: %w", err)
	}
	return nil
}

// GetSigningKey returns the signing key registered to the caller's Fabric ID.
func (s *SmartContract) GetSigningKey(ctx contractapi.TransactionContextInterface) (*SigningKeyRecord, error) {
	senderID, mspID, err := getSubmittingIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := ctx.GetStub().GetState(signingKeyStateKey(mspID, senderID))
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key: %w", err)
	}
	if value == nil {
		return nil, fmt.Errorf("no signing key is registered for this Fabric identity")
	}
	var record SigningKeyRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return nil, fmt.Errorf("failed to decode signing-key record: %w", err)
	}
	return &record, nil
}

// RecordMessage verifies a message signature using the signing key registered
// to the authenticated submitting Fabric identity, then writes only the
// message digest and metadata. Args: messageID, receiver, messageHash, signatureBase64.
func (s *SmartContract) RecordMessage(
	ctx contractapi.TransactionContextInterface,
	messageID string,
	receiver string,
	messageHash string,
	signatureBase64 string,
) error {
	messageID = strings.TrimSpace(messageID)
	receiver = strings.TrimSpace(receiver)
	if !messageIDPattern.MatchString(messageID) {
		return fmt.Errorf("message ID must contain 1-128 letters, numbers, dots, underscores, or hyphens")
	}
	if receiver == "" {
		return fmt.Errorf("receiver is required")
	}
	digest, normalizedHash, err := parseSHA256Hash(messageHash)
	if err != nil {
		return err
	}
	signature, err := decodeBase64Signature(signatureBase64)
	if err != nil {
		return err
	}
	senderID, mspID, err := getSubmittingIdentity(ctx)
	if err != nil {
		return err
	}
	signingKey, err := s.readSigningKeyForIdentity(ctx, senderID, mspID)
	if err != nil {
		return err
	}
	publicKey, _, algorithm, err := parseAndValidatePublicKey(signingKey.PublicKeyPEM, signingKey.SignatureAlgorithm)
	if err != nil {
		return fmt.Errorf("registered signing key is invalid: %w", err)
	}
	if err := verifyPublicKeySignature(publicKey, digest, signature, algorithm); err != nil {
		return fmt.Errorf("message signature verification failed: %w", err)
	}

	key := messageKeyPrefix + messageID
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to check message existence: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("message %s already exists", messageID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get transaction timestamp: %w", err)
	}
	if txTimestamp == nil {
		return fmt.Errorf("transaction timestamp is unavailable")
	}
	record := MessageRecord{
		MessageID:            messageID,
		Sender:               senderID,
		SenderMSPID:          mspID,
		Receiver:             receiver,
		MessageHash:          normalizedHash,
		Signature:            strings.TrimSpace(signatureBase64),
		SignatureAlgorithm:   algorithm,
		SignerKeyFingerprint: signingKey.PublicKeySHA256,
		CreatedAt:            time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano),
		TransactionID:        ctx.GetStub().GetTxID(),
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to encode message record: %w", err)
	}
	if err := ctx.GetStub().PutState(key, recordJSON); err != nil {
		return fmt.Errorf("failed to store message record: %w", err)
	}
	return nil
}

// ReadMessage returns the signed message metadata for a message ID.
func (s *SmartContract) ReadMessage(ctx contractapi.TransactionContextInterface, messageID string) (*MessageRecord, error) {
	messageID = strings.TrimSpace(messageID)
	if !messageIDPattern.MatchString(messageID) {
		return nil, fmt.Errorf("invalid message ID")
	}
	recordJSON, err := ctx.GetStub().GetState(messageKeyPrefix + messageID)
	if err != nil {
		return nil, fmt.Errorf("failed to read message record: %w", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("message %s does not exist", messageID)
	}
	var record MessageRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return nil, fmt.Errorf("failed to decode message record: %w", err)
	}
	return &record, nil
}

// MessageExists reports whether a message ID has already been recorded.
func (s *SmartContract) MessageExists(ctx contractapi.TransactionContextInterface, messageID string) (bool, error) {
	messageID = strings.TrimSpace(messageID)
	if !messageIDPattern.MatchString(messageID) {
		return false, fmt.Errorf("invalid message ID")
	}
	value, err := ctx.GetStub().GetState(messageKeyPrefix + messageID)
	if err != nil {
		return false, fmt.Errorf("failed to check message existence: %w", err)
	}
	return value != nil, nil
}

// VerifyMessageHash compares a supplied SHA-256 digest with the stored digest.
func (s *SmartContract) VerifyMessageHash(ctx contractapi.TransactionContextInterface, messageID string, submittedHash string) (bool, error) {
	_, normalizedHash, err := parseSHA256Hash(submittedHash)
	if err != nil {
		return false, err
	}
	record, err := s.ReadMessage(ctx, messageID)
	if err != nil {
		return false, err
	}
	return record.MessageHash == normalizedHash, nil
}

// GetAllMessages returns all message records in the message key range.
func (s *SmartContract) GetAllMessages(ctx contractapi.TransactionContextInterface) ([]*MessageRecord, error) {
	return s.getMessages(ctx, "", "")
}

// GetMessagesBySender returns message records for a Fabric client identity ID.
func (s *SmartContract) GetMessagesBySender(ctx contractapi.TransactionContextInterface, sender string) ([]*MessageRecord, error) {
	sender = strings.TrimSpace(sender)
	if sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	return s.getMessages(ctx, "sender", sender)
}

// GetMessagesByReceiver returns message records for a receiver identifier.
func (s *SmartContract) GetMessagesByReceiver(ctx contractapi.TransactionContextInterface, receiver string) ([]*MessageRecord, error) {
	receiver = strings.TrimSpace(receiver)
	if receiver == "" {
		return nil, fmt.Errorf("receiver is required")
	}
	return s.getMessages(ctx, "receiver", receiver)
}

func (s *SmartContract) getMessages(ctx contractapi.TransactionContextInterface, field string, value string) ([]*MessageRecord, error) {
	iterator, err := ctx.GetStub().GetStateByRange(messageKeyPrefix, "message;")
	if err != nil {
		return nil, fmt.Errorf("failed to query message ledger: %w", err)
	}
	defer iterator.Close()

	var records []*MessageRecord
	for iterator.HasNext() {
		entry, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read message record: %w", err)
		}
		var record MessageRecord
		if err := json.Unmarshal(entry.GetValue(), &record); err != nil {
			return nil, fmt.Errorf("failed to decode message record: %w", err)
		}
		switch field {
		case "sender":
			if record.Sender != value {
				continue
			}
		case "receiver":
			if record.Receiver != value {
				continue
			}
		}
		records = append(records, &record)
	}
	return records, nil
}

func (s *SmartContract) readSigningKeyForIdentity(
	ctx contractapi.TransactionContextInterface,
	senderID string,
	mspID string,
) (*SigningKeyRecord, error) {
	value, err := ctx.GetStub().GetState(signingKeyStateKey(mspID, senderID))
	if err != nil {
		return nil, fmt.Errorf("failed to read registered signing key: %w", err)
	}
	if value == nil {
		return nil, fmt.Errorf("no signing key is registered for this Fabric identity")
	}
	var record SigningKeyRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return nil, fmt.Errorf("failed to decode signing-key record: %w", err)
	}
	return &record, nil
}

func getSubmittingIdentity(ctx contractapi.TransactionContextInterface) (string, string, error) {
	if ctx.GetClientIdentity() == nil {
		return "", "", fmt.Errorf("submitting Fabric client identity is unavailable")
	}
	senderID, err := ctx.GetClientIdentity().GetID()
	if err != nil || strings.TrimSpace(senderID) == "" {
		return "", "", fmt.Errorf("unable to identify submitting Fabric client")
	}
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil || strings.TrimSpace(mspID) == "" {
		return "", "", fmt.Errorf("unable to identify submitting organization")
	}
	return senderID, mspID, nil
}

func signingKeyStateKey(mspID string, senderID string) string {
	identityHash := sha256.Sum256([]byte(mspID + "\x00" + senderID))
	return signingKeyKeyPrefix + hex.EncodeToString(identityHash[:])
}

func makeSigningKeyChallenge(mspID string, senderID string, fingerprint string, algorithm string) string {
	return strings.Join([]string{
		signingKeyChallengeV1,
		mspID,
		senderID,
		fingerprint,
		algorithm,
	}, "\n")
}

func parseAndValidatePublicKey(publicKeyPEM string, algorithm string) (any, string, string, error) {
	algorithm = strings.ToUpper(strings.TrimSpace(algorithm))
	block, _ := pem.Decode([]byte(strings.TrimSpace(publicKeyPEM)))
	if block == nil {
		return nil, "", "", fmt.Errorf("public key must be PEM encoded")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid public key: %w", err)
	}
	switch algorithm {
	case "ECDSA-SHA256":
		if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
			return nil, "", "", fmt.Errorf("ECDSA-SHA256 requires an ECDSA public key")
		}
	case "RSA-PSS-SHA256", "RSA-PKCS1V15-SHA256":
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 2048 {
			return nil, "", "", fmt.Errorf("RSA signature algorithms require an RSA key of at least 2048 bits")
		}
	case "ED25519":
		if _, ok := publicKey.(ed25519.PublicKey); !ok {
			return nil, "", "", fmt.Errorf("ED25519 requires an Ed25519 public key")
		}
	default:
		return nil, "", "", fmt.Errorf("unsupported signature algorithm %q", algorithm)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("unable to encode public key: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	return publicKey, hex.EncodeToString(fingerprint[:]), algorithm, nil
}

func parseSHA256Hash(value string) ([]byte, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != sha256.Size*2 {
		return nil, "", fmt.Errorf("message hash must be a 64-character SHA-256 hex digest")
	}
	digest, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, "", fmt.Errorf("message hash must be hexadecimal")
	}
	return digest, normalized, nil
}

func decodeBase64Signature(value string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("signature must be non-empty Base64 data")
	}
	return signature, nil
}

func verifyPublicKeySignature(publicKey any, digest []byte, signature []byte, algorithm string) error {
	switch algorithm {
	case "ECDSA-SHA256":
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	case "RSA-PSS-SHA256":
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok || rsa.VerifyPSS(key, crypto.SHA256, digest, signature, nil) != nil {
			return fmt.Errorf("RSA-PSS signature verification failed")
		}
	case "RSA-PKCS1V15-SHA256":
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature) != nil {
			return fmt.Errorf("RSA-PKCS1v15 signature verification failed")
		}
	case "ED25519":
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, digest, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %q", algorithm)
	}
	return nil
}
