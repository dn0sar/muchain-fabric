package txset

import (
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"fmt"
	"math/rand"
	"encoding/binary"
	"github.com/op/go-logging"
)

const (
	NUM_SEEDS  = 4
	SEED_BYTES = 8
	KEY_BYTES  = 32
)

var logger = logging.MustGetLogger("txsetcrypto")

// EncryptTxSetSpecification encrypts the txSetSpecification and returns the nonce necessary to generate the decryption keys.
func EncryptTxSetSpecification(specs [][]byte) ([]byte, [][]byte, error) {
	// Generate random initial value
	randNonces, err := primitives.GetRandomBytes(NUM_SEEDS * SEED_BYTES)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to generate initial randomness for the transaction encryption. (%s)", err)
	}
	// Read and combine the randomness from the seeded PRG
	txKeys := make([][]byte, len(specs))
	for i := range specs {
		txKeys[i] = make([]byte, KEY_BYTES)
	}
	tempKey := make([]byte, KEY_BYTES)
	for i := 0; i < NUM_SEEDS; i++ {
		rand.Seed(int64(binary.BigEndian.Uint64(randNonces[i * SEED_BYTES : (i + 1) * SEED_BYTES])))
		for j := range specs {
			_, err := rand.Read(tempKey)
			if err != nil {
				return nil, nil, fmt.Errorf("Unable to generate random key for the transaction encryption. (%s)", err)
			}
			xorBytes(txKeys[j], tempKey)
		}
	}
	encSpecs := make([][]byte, len(specs))
	// Encrypt the given bytes
	for i := range specs {
		encSpecs[i], err = primitives.CBCPKCS7Encrypt(txKeys[i], specs[i])
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to encrypt transaction. Err: [%s]", err)
		}
	}
	return randNonces, encSpecs, nil
}

func DecryptTxSetSpecification(nonce, spec []byte, index uint64) ([]byte, error) {
	key, err := GenerateKeyForTransaction(nonce, index)
	if err != nil {
		return nil, err
	}
	return primitives.CBCPKCS7Decrypt(key, spec)
}

func GenerateKeyForTransaction(nonce []byte, index uint64) ([]byte, error) {
	key := make([]byte, KEY_BYTES)
	tempKey := make([]byte, KEY_BYTES)
	for i := 0; i < NUM_SEEDS; i++ {
		rand.Seed(int64(binary.BigEndian.Uint64(nonce[i * SEED_BYTES : (i + 1) * SEED_BYTES])))
		for j := 0; uint64(j) <= index; j++ {
			_, err := rand.Read(tempKey)
			if err != nil {
				return nil, err
			}
		}
		xorBytes(key, tempKey)
	}
	return key, nil
}

// performs a xor of the content of the second array into the first
func xorBytes(first, second []byte) {
	for i := 0; i < len(first); i++ {
		if i >= len(second) {
			break
		}
		first[i] = first[i] ^ second[i]
	}
}