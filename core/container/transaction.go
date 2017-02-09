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

var containerLogger = logging.MustGetLogger("container_transaction")

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
	//REVIEW: until hyperledger clients can encrypt transactions without asking peer to do it for them fabric's security for alternative versions cannot be enabled
	/* var sec crypto.Client

	if comm.SecurityEnabled() {
		if containerLogger.IsEnabledFor(logging.DEBUG) {
			containerLogger.Debugf("Initializing secure devops using context %s", spec.SecureContext)
		}
		sec, err = crypto.InitClient(spec.SecureContext, nil)
		if sec != nil {
			defer crypto.CloseClient(sec)
		}
		if err != nil {
			return nil, err
		}

		// remove the security context since we are no longer need it down stream
		spec.SecureContext = ""

		if containerLogger.IsEnabledFor(logging.DEBUG) {
			containerLogger.Debugf("Creating secure transaction %s", transID)
		}
		tx, err = sec.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID, spec.Attributes...)
		if nil != err {
			return nil, err
		}
	} else { */
		containerLogger.Debugf("Creating deployment transaction (%s)", transID)
		tx, err = pb.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID)
		if err != nil {
			return nil, fmt.Errorf("Error deploying chaincode: %s ", err)
		}
	//}
	return tx, nil
}

func NewExecTransaction(spec *pb.ChaincodeInvocationSpec) (*pb.Transaction, error) {
	var uuid string
	var err error
	var tx *pb.Transaction
	var customIDgenAlg = strings.ToLower(spec.IdGenerationAlg)

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

	//REVIEW: until hyperledger clients can encrypt transactions without asking peer to do it for them fabric's security for alternative versions cannot be enabled
	/*var sec crypto.Client
	if comm.SecurityEnabled() {
		containerLogger.Debugf("Initializing secure devops using context %s", spec.ChaincodeSpec.SecureContext)
		sec, err = crypto.InitClient(spec.ChaincodeSpec.SecureContext, nil)
		if sec != nil {
			defer crypto.CloseClient(sec)
		}
		if nil != err {
			return nil, err
		}
		// remove the security context since we are no longer need it down stream
		spec.ChaincodeSpec.SecureContext = ""
	}

	if sec != nil {
		containerLogger.Debugf("Creating secure invocation transaction %s", uuid)
		tx, err = sec.NewChaincodeExecute(spec, uuid, spec.ChaincodeSpec.Attributes...)
		if nil != err {
			return nil, err
		}
	} else {*/
		containerLogger.Debugf("Creating invocation transaction (%s)", uuid)
		tx, err = pb.NewChaincodeExecute(spec, uuid, pb.ChaincodeAction_CHAINCODE_INVOKE)
		if nil != err {
			return nil, err
		}
	//}
	return tx, nil
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
		tx, err = NewExecTransaction(txSpec.GetInvocationSpec())
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
		Nonce:        					tx.Nonce,
		ToValidators: 					tx.ToValidators,
		Cert:         					tx.Cert,
		Signature:    					tx.Signature,
	}
	return encapsulatedTx, nil
}

func EncapsulateInBlockToTraditionalTx(inBlock *pb.InBlockTransaction) (*pb.Transaction, error) {
	var marshaledTx []byte
	var err error
	switch tx := inBlock.Transaction.(type) {
	case *pb.InBlockTransaction_TransactionSet:
		marshaledTx, err = proto.Marshal(tx.TransactionSet)
	case *pb.InBlockTransaction_MutantTransaction:
		marshaledTx, err = proto.Marshal(tx.MutantTransaction)
	case *pb.InBlockTransaction_SetStQueryTransaction:
		marshaledTx, err = proto.Marshal(tx.SetStQueryTransaction)
	default:
		return  nil, fmt.Errorf("InBlockTransactionType not supported type: %v", inBlock.Transaction)
	}
	if  err != nil {
		return nil, fmt.Errorf("Unable to marshal the given transaction %#v, err; %s", inBlock.Transaction, err)
	}

	tx := &pb.Transaction{
		Payload: marshaledTx,
		Metadata: inBlock.Metadata,
		Txid: inBlock.Txid,
		Timestamp: inBlock.Timestamp,
		ConfidentialityLevel: inBlock.ConfidentialityLevel,
		ConfidentialityProtocolVersion: inBlock.ConfidentialityProtocolVersion,
		Nonce: inBlock.Nonce,
		ToValidators: inBlock.ToValidators,
		Cert: inBlock.Cert,
		Signature: inBlock.Signature,
	}
	return tx, nil
}
