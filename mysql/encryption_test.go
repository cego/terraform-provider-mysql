package mysql

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func TestEncryptValue(t *testing.T) {
	entity, err := openpgp.NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := bytes.NewBuffer(nil)
	if err := entity.Serialize(pubKey); err != nil {
		t.Fatal(err)
	}

	key, err := retrieveGPGKey(base64.StdEncoding.EncodeToString(pubKey.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	fingerprint, encrypted, err := encryptValue(key, "s3cr3t", "MySQL Password")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint); fingerprint != want {
		t.Fatalf("fingerprint = %s, want %s", fingerprint, want)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), openpgp.EntityList{entity}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "s3cr3t" {
		t.Fatalf("decrypted = %q, want %q", plaintext, "s3cr3t")
	}
}

func TestEncryptValue_invalidKey(t *testing.T) {
	if _, _, err := encryptValue("not-a-key", "s3cr3t", "MySQL Password"); err == nil {
		t.Fatal("expected error for invalid key")
	}
}
