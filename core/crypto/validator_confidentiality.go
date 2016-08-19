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

package crypto

import (
	"encoding/asn1"
	"errors"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
	obc "github.com/hyperledger/fabric/protos"
//	"encoding/binary"
	"encoding/binary"
)

func (validator *validatorImpl) deepCloneTransaction(tx *obc.InBlockTransaction) (*obc.InBlockTransaction, error) {
	raw, err := proto.Marshal(tx)
	if err != nil {
		validator.Errorf("Failed cloning transaction [%s].", err.Error())

		return nil, err
	}

	clone := &obc.InBlockTransaction{}
	err = proto.Unmarshal(raw, clone)
	if err != nil {
		validator.Errorf("Failed cloning transaction [%s].", err.Error())

		return nil, err
	}

	return clone, nil
}

func (validator *validatorImpl) deepCloneAndDecryptTx(tx *obc.InBlockTransaction) (*obc.InBlockTransaction, error) {
	switch tx.ConfidentialityProtocolVersion {
	case "1.2":
		return validator.deepCloneAndDecryptTx1_2(tx)
	}
	return nil, utils.ErrInvalidProtocolVersion
}

//Returns an InBlockTransaction with the currentDefault decrypted or with the Mutable decrypted!
func (validator *validatorImpl) deepCloneAndDecryptTx1_2(tx *obc.InBlockTransaction) (*obc.InBlockTransaction, error) {
	if tx.Nonce == nil || len(tx.Nonce) == 0 {
		return nil, errors.New("Failed decrypting payload. Invalid nonce.")
	}

	// clone tx
	clone, err := validator.deepCloneTransaction(tx)
	if err != nil {
		validator.Errorf("Failed deep cloning [%s].", err.Error())
		return nil, err
	}

	var ccPrivateKey primitives.PrivateKey

	validator.Debug("Extract transaction key...")

	// Derive transaction key
	cipher, err := validator.eciesSPI.NewAsymmetricCipherFromPrivateKey(validator.chainPrivateKey)
	if err != nil {
		validator.Errorf("Failed init decryption engine [%s].", err.Error())
		return nil, err
	}

	msgToValidatorsRaw, err := cipher.Process(tx.ToValidators)
	if err != nil {
		validator.Errorf("Failed decrypting message to validators [% x]: [%s].", tx.ToValidators, err.Error())
		return nil, err
	}

	msgToValidators := new(chainCodeValidatorMessage1_2)
	_, err = asn1.Unmarshal(msgToValidatorsRaw, msgToValidators)
	if err != nil {
		validator.Errorf("Failed unmarshalling message to validators [%s].", err.Error())
		return nil, err
	}

	validator.Debugf("Deserializing transaction key [% x].", msgToValidators.PrivateKey)
	ccPrivateKey, err = validator.eciesSPI.DeserializePrivateKey(msgToValidators.PrivateKey)
	if err != nil {
		validator.Errorf("Failed deserializing transaction key [%s].", err.Error())
		return nil, err
	}

	validator.Debug("Extract transaction key...done")

	cipher, err = validator.eciesSPI.NewAsymmetricCipherFromPrivateKey(ccPrivateKey)
	if err != nil {
		validator.Errorf("Failed init transaction decryption engine [%s].", err.Error())
		return nil, err
	}

	// Decrypt metadata of the InBlockTransaction
	if len(clone.Metadata) != 0 {
		metadata, err := cipher.Process(clone.Metadata)
		if err != nil {
			validator.Errorf("Failed decrypting metadata [%s].", err.Error())
			return nil, err
		}
		clone.Metadata = metadata
	}

	switch tx.Transaction.(type) {
	case *obc.InBlockTransaction_TransactionSet:
		//TODO take the current default instead
		currDefault := clone.GetTransactionSet().Transactions[clone.GetTransactionSet().DefaultInx]
		validator.Debugf("Transaction kind: [Set], current default type: [%s].", currDefault.Type)
		// Decrypt Payload
		payload, err := cipher.Process(currDefault.Payload)
		if err != nil {
			validator.Errorf("Failed decrypting payload [%s].", err.Error())
			return nil, err
		}
		currDefault.Payload = payload

		// Decrypt ChaincodeID
		chaincodeID, err := cipher.Process(currDefault.ChaincodeID)
		if err != nil {
			validator.Errorf("Failed decrypting chaincode [%s].", err.Error())
			return nil, err
		}
		currDefault.ChaincodeID = chaincodeID

		// Decrypt metadata
		if len(currDefault.Metadata) != 0 {
			metadata, err := cipher.Process(currDefault.Metadata)
			if err != nil {
				validator.Errorf("Failed decrypting metadata [%s].", err.Error())
				return nil, err
			}
			currDefault.Metadata = metadata
		}
	case *obc.InBlockTransaction_MutantTransaction:
		validator.Debug("Transaction kind: [Mutant]")
		mutant := clone.GetMutantTransaction()
		// Decrypt block ref
		blockRef, err := cipher.Process(mutant.BlockRef)
		if err != nil {
			validator.Errorf("Failed decrypting block number for mutant transaction [%s].", err.Error())
			return nil, err
		}
		mutant.BlockRef = blockRef

		// Decrypt txID
		txRef, err := cipher.Process(mutant.TxRef)
		if err != nil {
			validator.Errorf("Failed decrypting transaction reference ID for mutant transaction [%s].", err.Error())
			return nil, err
		}
		mutant.TxRef = txRef

		// Decrypt index
		inxInBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(inxInBytes, mutant.Index)
		inx, err := cipher.Process(inxInBytes)
		if err != nil {
			validator.Errorf("Failed decrypting new transaction index for mutant transaction [%s].", err.Error())
			return nil, err
		}
		mutant.Index = binary.LittleEndian.Uint32(inx)
	}

	return clone, nil
}
