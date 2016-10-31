package container

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"strings"
	"encoding/asn1"
	"github.com/op/go-logging"
	pb "github.com/hyperledger/fabric/protos"
	"errors"
	"github.com/hyperledger/fabric/core/util"
)

var containerLogger = logging.MustGetLogger("core_util")

func NewDeployTransaction(spec *pb.ChaincodeSpec) (*pb.Transaction, error) {
	// get the deployment spec
	packageBytes, err := GetChaincodePackageBytes(spec)
	if err != nil {
		err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
		containerLogger.Error(fmt.Sprintf("%s", err))
		return nil, err
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: packageBytes}

	_, err = proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		containerLogger.Errorf("chaincode deployment spec successfully generated, but unable to serialize it (%s)", err)
		return nil, fmt.Errorf("chaincode deployment spec successfully generated, but unable to serialize it (%s)", err)
	}

	// Now create the Transaction
	transID := chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name

	var tx *pb.Transaction
	containerLogger.Debugf("Creating deployment transaction (%s)", transID)
	tx, err = pb.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID)
	if err != nil {
		return nil, fmt.Errorf("Error deploying chaincode: %s ", err)
	}

	return tx, nil
}

func NewExecTransaction(spec *pb.ChaincodeInvocationSpec, invokeTx bool) (*pb.Transaction, error) {
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

	if containerLogger.IsEnabledFor(logging.DEBUG) {
		containerLogger.Debugf("Creating invocation transaction (%s)", uuid)
	}
	var t pb.ChaincodeAction
	if invokeTx {
		t = pb.ChaincodeAction_CHAINCODE_INVOKE
	} else {
		t = pb.ChaincodeAction_CHAINCODE_QUERY
	}
	tx, err := pb.NewChaincodeExecute(spec, uuid, t)
	if nil != err {
		return nil, err
	}
	return tx, err
}

func TransactionFromTxSpec(txSpec *pb.TxSpec) (tx *pb.Transaction, err error) {
	switch txSpec.Action {
	case pb.ChaincodeAction_CHAINCODE_DEPLOY:
		if txSpec.GetCodeSpec() == nil {
			return nil, errors.New("Trying to reconstruct a Deploy transaction without a valid Chaincode Specification.")
		}
		tx, err = NewDeployTransaction(txSpec.GetCodeSpec())
		if err != nil {
			return nil, err
		}
	case pb.ChaincodeAction_CHAINCODE_INVOKE:
		if txSpec.GetInvocationSpec() == nil {
			return nil, errors.New("Trying to add a Invoke transaction to the tx set without a valid Invocation Specification.")
		}
		tx, err = NewExecTransaction(txSpec.GetInvocationSpec(), true)
		if err != nil {
			return nil, err
		}
	case pb.ChaincodeAction_CHAINCODE_QUERY:
		// This should not happen, since checks to exclude query transactions
		// should have been performed before calling this function
		return nil, errors.New("Cannot to create a tx set containing a query transaction")
	default:
		return nil, fmt.Errorf("Transaction type not supported to be part of a transactins set. Type: %s", txSpec.Action)
	}
	return
}

func EncapsulateTransactionToInBlock(tx *pb.Transaction) (*pb.InBlockTransaction, error) {
	marshaledTx, err := proto.Marshal(tx)
	if  err != nil {
		return nil, fmt.Errorf("Unable to marshal the given transaction %#v, err; %s", tx, err)
	}
	encapsulatedTx := &pb.InBlockTransaction{
		Transaction:                    &pb.InBlockTransaction_TransactionSet{TransactionSet: &pb.TransactionSet{Transactions: [][]byte{marshaledTx}, DefaultInx: 0}},
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
	return encapsulatedTx, nil
}

