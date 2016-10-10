/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stcomm

import (
	"bytes"
	"encoding/binary"
)

var stateKeyDelimiter = []byte{0x00}

// ConstructCompositeKey returns a []byte that uniquely represents a given chaincodeID and key.
// This assumes that chaincodeID does not contain a 0x00 byte, but the key may
// TODO:enforce this restriction on chaincodeID or use length prefixing here instead of delimiter
func ConstructCompositeKey(chaincodeID string, key string) []byte {
	return bytes.Join([][]byte{[]byte(chaincodeID), []byte(key)}, stateKeyDelimiter)
}

// DecodeCompositeKey decodes the compositeKey constructed by ConstructCompositeKey method
// back to the original chaincodeID and key form
func DecodeCompositeKey(compositeKey []byte) (string, string) {
	split := bytes.SplitN(compositeKey, stateKeyDelimiter, 2)
	return string(split[0]), string(split[1])
}

// ConstructTxSetKey returns a []byte that uniquely represents a given txSetID
func ConstructTxSetKey(txSetID string) []byte {
	return []byte(txSetID)
}
// GetTxSetIDfromKey returns the txSetID that was used to create the key given as input.
// i.e. the following is guaranteed GetTxSetIDfromKey(ConstructTxSetKey(txSetID)) == txSetID
func GetTxSetIDfromKey(txSetKey []byte) string {
	return string(txSetKey)
}

// Copy returns a copy of given bytes
func Copy(src []byte) []byte {
	dest := make([]byte, len(src))
	copy(dest, src)
	return dest
}

func EncodeStateDeltaKey(blockNumber uint64) []byte {
	return encodeUint64(blockNumber)
}

func DecodeStateDeltaKey(dbkey []byte) uint64 {
	return decodeToUint64(dbkey)
}

func encodeUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, number)
	return bytes
}

func decodeToUint64(bytes []byte) uint64 {
	return binary.BigEndian.Uint64(bytes)
}
