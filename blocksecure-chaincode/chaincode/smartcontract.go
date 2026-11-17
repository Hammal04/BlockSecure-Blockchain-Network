package chaincode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
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

const messageKeyPrefix = "message:"

var messageIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SmartContract stores verifiable message metadata on the BlockSecure ledger.
// Plaintext messages and private signing keys must remain off-chain.
type SmartContract struct {
	contractapi.Contract
}

// MessageRecord is the immutable on-chain record for a signed message digest.
type MessageRecord struct {
	MessageID          string `json:"messageId"`
	Sender             string `json:"sender"`
	Receiver           string `json:"receiver"`
	MessageHash        string `json:"messageHash"`
	Signature          string `json:"signature"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	PublicKeyPEM       string `json:"publicKeyPem"`
	CreatedAt          string `json:"createdAt"`
	TransactionID      string `json:"transactionId"`
}

// RecordMessage records a SHA-256 message digest and verifies the sender's
// digital signature before writing the record. The signature is Base64-encoded
// and signs the 32 raw bytes represented by messageHash (not the hex text).
//
// Supported SignatureAlgorithm values:
//   - ECDSA-SHA256 (ASN.1 DER signature)
//   - RSA-PSS-SHA256
//   - RSA-PKCS1v15-SHA256
//   - ED25519 (signature over the 32-byte digest)
//
// The message plaintext and the sender's private key are never stored on-chain.
func (s *SmartContract) RecordMessage(
	ctx contractapi.TransactionContextInterface,
	messageID string,
	sender string,
	receiver string,
	messageHash string,
	signature string,
	signatureAlgorithm string,
	publicKeyPEM string,
) error {
	messageID = strings.TrimSpace(messageID)
	sender = strings.TrimSpace(sender)
	receiver = strings.TrimSpace(receiver)
	signature = strings.TrimSpace(signature)
	signatureAlgorithm = strings.ToUpper(strings.TrimSpace(signatureAlgorithm))

	if !messageIDPattern.MatchString(messageID) {
		return fmt.Errorf("message ID must contain 1-128 letters, numbers, dots, underscores, or hyphens")
	}
	if sender == "" || receiver == "" {
		return fmt.Errorf("sender and receiver are required")
	}

	digest, normalizedHash, err := parseSHA256Hash(messageHash)
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(signatureBytes) == 0 {
		return fmt.Errorf("signature must be non-empty Base64 data")
	}
	if err := verifyDigestSignature(digest, signatureBytes, signatureAlgorithm, publicKeyPEM); err != nil {
		return err
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
		MessageID:          messageID,
		Sender:             sender,
		Receiver:           receiver,
		MessageHash:        normalizedHash,
		Signature:          signature,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyPEM:       strings.TrimSpace(publicKeyPEM),
		CreatedAt:          time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano),
		TransactionID:      ctx.GetStub().GetTxID(),
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

// ReadMessage returns the on-chain record for a message ID.
func (s *SmartContract) ReadMessage(ctx contractapi.TransactionContextInterface, messageID string) (*MessageRecord, error) {
	if !messageIDPattern.MatchString(strings.TrimSpace(messageID)) {
		return nil, fmt.Errorf("invalid message ID")
	}
	recordJSON, err := ctx.GetStub().GetState(messageKeyPrefix + strings.TrimSpace(messageID))
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
	if !messageIDPattern.MatchString(strings.TrimSpace(messageID)) {
		return false, fmt.Errorf("invalid message ID")
	}
	value, err := ctx.GetStub().GetState(messageKeyPrefix + strings.TrimSpace(messageID))
	if err != nil {
		return false, fmt.Errorf("failed to check message existence: %w", err)
	}
	return value != nil, nil
}

// VerifyMessageHash compares a supplied SHA-256 digest with the digest
// recorded on-chain. This checks ledger consistency; it does not retrieve
// plaintext message contents.
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

// GetAllMessages returns every message record stored under the message: prefix.
func (s *SmartContract) GetAllMessages(ctx contractapi.TransactionContextInterface) ([]*MessageRecord, error) {
	return s.getMessages(ctx, "", "")
}

// GetMessagesBySender returns message records for a sender identity.
func (s *SmartContract) GetMessagesBySender(ctx contractapi.TransactionContextInterface, sender string) ([]*MessageRecord, error) {
	sender = strings.TrimSpace(sender)
	if sender == "" {
		return nil, fmt.Errorf("sender is required")
	}
	return s.getMessages(ctx, "sender", sender)
}

// GetMessagesByReceiver returns message records for a receiver identity.
func (s *SmartContract) GetMessagesByReceiver(ctx contractapi.TransactionContextInterface, receiver string) ([]*MessageRecord, error) {
	receiver = strings.TrimSpace(receiver)
	if receiver == "" {
		return nil, fmt.Errorf("receiver is required")
	}
	return s.getMessages(ctx, "receiver", receiver)
}

func (s *SmartContract) getMessages(ctx contractapi.TransactionContextInterface, field string, value string) ([]*MessageRecord, error) {
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to query ledger: %w", err)
	}
	defer iterator.Close()

	var records []*MessageRecord
	for iterator.HasNext() {
		entry, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read ledger entry: %w", err)
		}
		if !strings.HasPrefix(entry.GetKey(), messageKeyPrefix) {
			continue
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

func parseSHA256Hash(value string) ([]byte, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) != 64 {
		return nil, "", fmt.Errorf("message hash must be a 64-character SHA-256 hex digest")
	}
	digest, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, "", fmt.Errorf("message hash must be hexadecimal")
	}
	return digest, normalized, nil
}

func verifyDigestSignature(digest []byte, signature []byte, algorithm string, publicKeyPEM string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(publicKeyPEM)))
	if block == nil {
		return fmt.Errorf("public key must be PEM encoded")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

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
