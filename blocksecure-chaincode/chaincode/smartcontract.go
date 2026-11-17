package chaincode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

const messageKeyPrefix = "message:"

var messageIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SmartContract exposes BlockSecure message-integrity transactions.
// Message plaintext and private keys must remain off-chain.
type SmartContract struct {
	contractapi.Contract
}

// MessageRecord stores verifiable metadata and a signed SHA-256 digest.
type MessageRecord struct {
	MessageID          string `json:"messageId"`
	Sender             string `json:"sender"`
	SenderMSPID        string `json:"senderMspId"`
	SenderCertSHA256   string `json:"senderCertSha256"`
	Receiver           string `json:"receiver"`
	MessageHash        string `json:"messageHash"`
	Signature          string `json:"signature"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	CreatedAt          string `json:"createdAt"`
	TransactionID      string `json:"transactionId"`
}

// RecordMessage validates the caller's digital signature using the X.509
// certificate associated with the submitting Fabric identity, then records
// only the message digest and metadata. The sender cannot be spoofed through
// an argument: it is derived from the authenticated Fabric client identity.
//
// Args: messageID, receiver, messageHash, signatureBase64, signatureAlgorithm.
// The application signature must cover SHA-256(message plaintext). ECDSA and
// RSA algorithms use the SHA-256 digest; Ed25519 signs the raw digest bytes.
func (s *SmartContract) RecordMessage(
	ctx contractapi.TransactionContextInterface,
	messageID string,
	receiver string,
	messageHash string,
	signatureBase64 string,
	signatureAlgorithm string,
) error {
	messageID = strings.TrimSpace(messageID)
	receiver = strings.TrimSpace(receiver)
	signatureAlgorithm = strings.ToUpper(strings.TrimSpace(signatureAlgorithm))

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
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureBase64))
	if err != nil || len(signature) == 0 {
		return fmt.Errorf("signature must be non-empty Base64 data")
	}

	clientIdentity := ctx.GetClientIdentity()
	if clientIdentity == nil {
		return fmt.Errorf("submitting Fabric client identity is unavailable")
	}
	senderID, err := clientIdentity.GetID()
	if err != nil || strings.TrimSpace(senderID) == "" {
		return fmt.Errorf("unable to identify submitting Fabric client")
	}
	mspID, err := clientIdentity.GetMSPID()
	if err != nil || strings.TrimSpace(mspID) == "" {
		return fmt.Errorf("unable to identify submitting organization")
	}
	certificate, err := clientIdentity.GetX509Certificate()
	if err != nil || certificate == nil {
		return fmt.Errorf("submitting identity must use an X.509 certificate")
	}
	if err := verifyPublicKeySignature(certificate.PublicKey, digest, signature, signatureAlgorithm); err != nil {
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

	certificateDigest := sha256.Sum256(certificate.Raw)
	record := MessageRecord{
		MessageID:          messageID,
		Sender:             senderID,
		SenderMSPID:        mspID,
		SenderCertSHA256:   hex.EncodeToString(certificateDigest[:]),
		Receiver:           receiver,
		MessageHash:        normalizedHash,
		Signature:          strings.TrimSpace(signatureBase64),
		SignatureAlgorithm: signatureAlgorithm,
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
// This confirms ledger consistency; it cannot inspect off-chain plaintext.
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

// GetAllMessages returns all message records in the ledger namespace.
func (s *SmartContract) GetAllMessages(ctx contractapi.TransactionContextInterface) ([]*MessageRecord, error) {
	return s.getMessages(ctx, "", "")
}

// GetMessagesBySender returns message records for an authenticated sender ID.
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
	iterator, err := ctx.GetStub().GetStateByRange("message:", "message;")
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
	if len(normalized) != sha256.Size*2 {
		return nil, "", fmt.Errorf("message hash must be a 64-character SHA-256 hex digest")
	}
	digest, err := hex.DecodeString(normalized)
	if err != nil {
		return nil, "", fmt.Errorf("message hash must be hexadecimal")
	}
	return digest, normalized, nil
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
