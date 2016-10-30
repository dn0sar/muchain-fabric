package muchain

import (
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/hyperledger/fabric/protos"
	"fmt"
	"math/rand"
	"encoding/binary"
)

const (
	NUM_SEEDS  = 4
	SEED_BYTES = 8
	KEY_BYTES  = 32
)


// Encrypts the txSetSpecification and returns the nonce necessary to generate the decryption keys.
func encryptTxSetSpecification(specs []*pb.TxSpec) ([]byte, error) {
	// Generate random initial value
	randNonces, err := primitives.GetRandomBytes(NUM_SEEDS * SEED_BYTES)
	if err != nil {
		return nil, fmt.Errorf("Unable to generate initial randomness for the transaction encryption. (%s)", err)
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
				return nil, fmt.Errorf("Unable to generate random key for the transaction encryption. (%s)", err)
			}
			xorBytes(txKeys[j], tempKey)
		}
	}
	// Encrypt each field of each specification with the relevant key
	//for i := range specs {
	//	// TODO: ENCRYPT EACH FIELD HERE!!!
	//	specs[i]
	//}
	return nil, nil
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