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

package protos

import (
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/util"
	"github.com/op/go-logging"
	"github.com/hyperledger/fabric/core/container"
	"strings"
	"encoding/asn1"
	"errors"
)

var protosLogger = logging.MustGetLogger("protos_logger")

// Bytes returns this transaction as an array of bytes.
func (transaction *Transaction) Bytes() ([]byte, error) {
	data, err := proto.Marshal(transaction)
	if err != nil {
		logger.Errorf("Error marshalling transaction: %s", err)
		return nil, fmt.Errorf("Could not marshal transaction: %s", err)
	}
	return data, nil
}

// NewTransaction creates a new transaction. It defines the function to call,
// the chaincodeID on which the function should be called, and the arguments
// string. The arguments could be a string of JSON, but there is no strict
// requirement.
func NewTransaction(chaincodeID ChaincodeID, uuid string, function string, arguments []string) (*Transaction, error) {
	data, err := proto.Marshal(&chaincodeID)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal chaincode : %s", err)
	}
	transaction := new(Transaction)
	transaction.ChaincodeID = data
	transaction.Txid = uuid
	transaction.Timestamp = util.CreateUtcTimestamp()
	/*
		// Build the spec
		spec := &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_GOLANG,
			ChaincodeID: chaincodeID, ChaincodeInput: &pb.ChaincodeInput{Function: function, Args: arguments}}

		// Build the ChaincodeInvocationSpec message
		invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

		data, err := proto.Marshal(invocation)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal payload for chaincode invocation: %s", err)
		}
		transaction.Payload = data
	*/
	return transaction, nil
}

// NewChaincodeDeployTransaction is used to deploy chaincode.
func NewChaincodeDeployTransaction(chaincodeDeploymentSpec *ChaincodeDeploymentSpec, uuid string) (*Transaction, error) {
	transaction := new(Transaction)
	transaction.Type = ChaincodeAction_CHAINCODE_DEPLOY
	transaction.Txid = uuid
	transaction.Timestamp = util.CreateUtcTimestamp()
	cID := chaincodeDeploymentSpec.ChaincodeSpec.GetChaincodeID()
	if cID != nil {
		data, err := proto.Marshal(cID)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal chaincode : %s", err)
		}
		transaction.ChaincodeID = data
	}
	//if chaincodeDeploymentSpec.ChaincodeSpec.GetCtorMsg() != nil {
	//	transaction.Function = chaincodeDeploymentSpec.ChaincodeSpec.GetCtorMsg().Function
	//	transaction.Args = chaincodeDeploymentSpec.ChaincodeSpec.GetCtorMsg().Args
	//}
	data, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		logger.Errorf("Error mashalling payload for chaincode deployment: %s", err)
		return nil, fmt.Errorf("Could not marshal payload for chaincode deployment: %s", err)
	}
	transaction.Payload = data
	return transaction, nil
}

// NewChaincodeExecute is used to invoke chaincode.
func NewChaincodeExecute(chaincodeInvocationSpec *ChaincodeInvocationSpec, uuid string, typ ChaincodeAction) (*Transaction, error) {
	transaction := new(Transaction)
	transaction.Type = typ
	transaction.Txid = uuid
	transaction.Timestamp = util.CreateUtcTimestamp()
	cID := chaincodeInvocationSpec.ChaincodeSpec.GetChaincodeID()
	if cID != nil {
		data, err := proto.Marshal(cID)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal chaincode : %s", err)
		}
		transaction.ChaincodeID = data
	}
	data, err := proto.Marshal(chaincodeInvocationSpec)
	if err != nil {
		return nil, fmt.Errorf("Could not marshal payload for chaincode invocation: %s", err)
	}
	transaction.Payload = data
	return transaction, nil
}

type strArgs struct {
	Function string
	Args     []string
}

// UnmarshalJSON converts the string-based REST/JSON input to
// the []byte-based current ChaincodeInput structure.
func (c *ChaincodeInput) UnmarshalJSON(b []byte) error {
	sa := &strArgs{}
	err := json.Unmarshal(b, sa)
	if err != nil {
		return err
	}
	allArgs := sa.Args
	if sa.Function != "" {
		allArgs = append([]string{sa.Function}, sa.Args...)
	}
	c.Args = util.ToChaincodeArgs(allArgs...)
	return nil
}

func NewDeployTransaction(spec *ChaincodeSpec) (*Transaction, error) {
	// get the deployment spec
	packageBytes, err := container.GetChaincodePackageBytes(spec)
	if err != nil {
		err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
		protosLogger.Error(fmt.Sprintf("%s", err))
		return nil, err
	}
	chaincodeDeploymentSpec := &ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: packageBytes}

	chaincodeDSBytes, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		protosLogger.Errorf("chaincode deployment spec successfully generated, but unable to serialize it (%s)", err)
		return nil, fmt.Errorf("chaincode deployment spec successfully generated, but unable to serialize it (%s)", err)
	}

	// Now create the Transaction
	transID := chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name

	var tx *Transaction
	protosLogger.Debugf("Creating deployment transaction (%s)", transID)
	tx, err = NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID)
	if err != nil {
		return nil, chaincodeDSBytes, fmt.Errorf("Error deploying chaincode: %s ", err)
	}

	return tx, nil
}

func NewExecTransaction(spec *ChaincodeInvocationSpec, invokeTx bool) (*Transaction, error) {
	var uuid string
	var customIDgenAlg = strings.ToLower(spec.IdGenerationAlg)
	if invokeTx {
		if customIDgenAlg != "" {
			ctorbytes, err := asn1.Marshal(*spec.ChaincodeSpec.CtorMsg)
			if err != nil {
				return nil, fmt.Errorf("Error marshalling constructor: %s", err)
			}
			uuid, err = util.GenerateIDWithAlg(customIDgenAlg, ctorbytes)
			if err != nil {
				return nil, err
			}
		} else {
			uuid = util.GenerateUUID()
		}
	} else {
		uuid = util.GenerateUUID()
	}

	if protosLogger.IsEnabledFor(logging.DEBUG) {
		protosLogger.Debugf("Creating invocation transaction (%s)", uuid)
	}
	var t ChaincodeAction
	if invokeTx {
		t = ChaincodeAction_CHAINCODE_INVOKE
	} else {
		t = ChaincodeAction_CHAINCODE_QUERY
	}
	tx, err := NewChaincodeExecute(spec, uuid, t)
	if nil != err {
		return nil, err
	}
	return tx, err
}

func TransactionFromTxSpec(txSpec *TxSpec) (tx *Transaction, err error) {
	switch txSpec.Action {
	case ChaincodeAction_CHAINCODE_DEPLOY:
		if txSpec.GetCodeSpec() == nil {
			return nil, errors.New("Trying to reconstruct a Deploy transaction without a valid Chaincode Specification.")
		}
		tx, err = NewDeployTransaction(txSpec.GetCodeSpec())
		if err != nil {
			return nil, err
		}
	case ChaincodeAction_CHAINCODE_INVOKE:
		if txSpec.GetInvocationSpec() == nil {
			return nil, fmt.Errorf("Trying to add a Invoke transaction to the tx set without a valid Invocation Specification.")
		}
		tx, err = NewExecTransaction(txSpec.GetInvocationSpec(), true)
		if err != nil {
			return nil, err
		}
	case ChaincodeAction_CHAINCODE_QUERY:
		// This should not happen, since checks to exclude query transactions
		// should have been performed before calling this function
		return nil, fmt.Errorf("Cannot to create a tx set containing a query transaction")
	default:
		return nil, fmt.Errorf("Transaction type not supported to be part of a transactins set. Type: %s", txSpec.Action)
	}
	return
}

func EncapsulateTransactionToInBlock(tx *Transaction) (*InBlockTransaction, error) {
	marshalledTx, err := proto.Marshal(tx)
	if  err != nil {
		return nil, fmt.Errorf("Unable to marshal the given transaction %#v, err; %s", tx, err)
	}
	return &InBlockTransaction{
		Transaction:                    &InBlockTransaction_TransactionSet{&TransactionSet{Transactions: [][]byte{marshalledTx}, DefaultInx: 0}},
		Metadata:                       tx.Metadata,
		Txid:                           tx.Txid,
		Timestamp:                      tx.Timestamp,
		ConfidentialityLevel:           tx.ConfidentialityLevel,
		ConfidentialityProtocolVersion: tx.ConfidentialityProtocolVersion,
		Nonce:        tx.Nonce,
		ToValidators: tx.ToValidators,
		Cert:         tx.Cert,
		Signature:    tx.Signature,
	}
}
