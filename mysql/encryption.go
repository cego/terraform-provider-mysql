package mysql

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
)

const keybasePrefix = "keybase:"

// retrieveGPGKey returns pgpKey as is, or fetches the public key from keybase when prefixed with "keybase:".
func retrieveGPGKey(pgpKey string) (string, error) {
	if !strings.HasPrefix(pgpKey, keybasePrefix) {
		return pgpKey, nil
	}

	key, err := fetchKeybasePubkey(strings.TrimPrefix(pgpKey, keybasePrefix))
	if err != nil {
		return "", fmt.Errorf("Error retrieving Public Key for %s: %w", pgpKey, err)
	}
	return key, nil
}

// encryptValue encrypts value with the base64-encoded PGP public key and returns the key fingerprint and base64 ciphertext.
func encryptValue(encryptionKey, value, description string) (string, string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("Error encrypting %s: error decoding given PGP key: %w", description, err)
	}

	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(data)))
	if err != nil {
		return "", "", fmt.Errorf("Error encrypting %s: error parsing given PGP key: %w", description, err)
	}

	ctBuf := bytes.NewBuffer(nil)
	pt, err := openpgp.Encrypt(ctBuf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("Error encrypting %s: error setting up encryption for PGP message: %w", description, err)
	}
	if _, err := pt.Write([]byte(value)); err != nil {
		return "", "", fmt.Errorf("Error encrypting %s: error encrypting PGP message: %w", description, err)
	}
	if err := pt.Close(); err != nil {
		return "", "", fmt.Errorf("Error encrypting %s: error encrypting PGP message: %w", description, err)
	}

	fingerprint := fmt.Sprintf("%x", entity.PrimaryKey.Fingerprint)
	return fingerprint, base64.StdEncoding.EncodeToString(ctBuf.Bytes()), nil
}

// fetchKeybasePubkey returns the base64-encoded primary public key of a keybase user.
func fetchKeybasePubkey(username string) (string, error) {
	lookupURL := "https://keybase.io/_/api/1.0/user/lookup.json?fields=public_keys&usernames=" + url.QueryEscape(username)
	resp, err := cleanhttp.DefaultClient().Get(lookupURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		Status struct {
			Name string
		}
		Them []struct {
			PublicKeys struct {
				Primary struct {
					Bundle string
				}
			} `json:"public_keys"`
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Status.Name != "OK" {
		return "", fmt.Errorf("got non-OK response: %q", out.Status.Name)
	}
	if len(out.Them) != 1 || out.Them[0].PublicKeys.Primary.Bundle == "" {
		return "", fmt.Errorf("unable to fetch keys for user %q from keybase", username)
	}

	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(out.Them[0].PublicKeys.Primary.Bundle))
	if err != nil {
		return "", err
	}
	if len(entityList) != 1 || entityList[0] == nil {
		return "", fmt.Errorf("primary key could not be parsed for user %q", username)
	}

	serialized := bytes.NewBuffer(nil)
	if err := entityList[0].Serialize(serialized); err != nil {
		return "", fmt.Errorf("error serializing entity for user %q: %w", username, err)
	}
	return base64.StdEncoding.EncodeToString(serialized.Bytes()), nil
}
