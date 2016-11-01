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

package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	"encoding/asn1"
	"encoding/base64"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/chaincode/platforms"
	"github.com/hyperledger/fabric/core/container"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
	"encoding/hex"
)

var devopsLogger = logging.MustGetLogger("devops")

// NewDevopsServer creates and returns a new Devops server instance.
func NewDevopsServer(coord peer.MessageHandlerCoordinator) *Devops {
	d := new(Devops)
	d.coord = coord
	d.isSecurityEnabled = viper.GetBool("security.enabled")
	d.bindingMap = &bindingMap{m: make(map[string]crypto.TransactionHandler)}
	return d
}

// bindingMap Used to store map of binding to TransactionHandler
type bindingMap struct {
	sync.RWMutex
	m map[string]crypto.TransactionHandler
}

// Devops implementation of Devops services
type Devops struct {
	coord             peer.MessageHandlerCoordinator
	isSecurityEnabled bool
	bindingMap        *bindingMap
}

func (b *bindingMap) getKeyFromBinding(binding []byte) string {
	return base64.StdEncoding.EncodeToString(binding)
}

func (b *bindingMap) addBinding(bindingToAdd []byte, txHandler crypto.TransactionHandler) {
	b.Lock()
	defer b.Unlock()
	key := b.getKeyFromBinding(bindingToAdd)
	b.m[key] = txHandler
}

func (b *bindingMap) getTxHandlerForBinding(binding []byte) (crypto.TransactionHandler, error) {
	b.Lock()
	defer b.Unlock()
	key := b.getKeyFromBinding(binding)
	txHandler, ok := b.m[key]
	if ok != true {
		// TXhandler not found by key, return error
		return nil, fmt.Errorf("Transaction handler not found for binding key = %s", key)
	}
	return txHandler, nil
}

// Login establishes the security context with the Devops service
func (d *Devops) Login(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	if err := crypto.RegisterClient(secret.EnrollId, nil, secret.EnrollId, secret.EnrollSecret); nil != err {
		return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
	}
	return &pb.Response{Status: pb.Response_SUCCESS}, nil

	// TODO: Handle timeout and expiration
}

// Build builds the supplied chaincode image
func (*Devops) Build(context context.Context, spec *pb.ChaincodeSpec) (*pb.Response, error) {
	resp := &pb.Response{Status: pb.Response_FAILURE, Msg: nil}
	mode := viper.GetString("chaincode.mode")
	var codePackageBytes []byte
	if mode != chaincode.DevModeUserRunsChaincode {
		devopsLogger.Debugf("Received build request for chaincode spec: %v", spec)
		if err := CheckSpec(spec); err != nil {
			resp.Msg = []byte(err.Error())
			return resp, err
		}

		vm, err := container.NewVM()
		if err != nil {
			resp.Msg = []byte(err.Error())
			return resp, fmt.Errorf("Error getting vm: %s", err)
		}

		codePackageBytes, err = vm.BuildChaincodeContainer(spec)
		if err != nil {
			resp.Msg = []byte(err.Error())
			err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
			devopsLogger.Error(fmt.Sprintf("%s", err))
			return resp, err
		}
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
	chaincodeDSBytes, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		resp.Msg = []byte(err.Error())
		return resp, fmt.Errorf("Unable to Marshal the Chaincode Deployment Specification (%s).", err)
	}
	resp.Status = pb.Response_SUCCESS
	resp.Msg = chaincodeDSBytes
	return resp, nil
}

// get chaincode bytes
func (*Devops) getChaincodeBytes(spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	mode := viper.GetString("chaincode.mode")
	var codePackageBytes []byte
	if mode != chaincode.DevModeUserRunsChaincode {
		devopsLogger.Debugf("Received build request for chaincode spec: %v", spec)
		var err error
		if err = CheckSpec(spec); err != nil {
			return nil, err
		}

		codePackageBytes, err = container.GetChaincodePackageBytes(spec)
		if err != nil {
			err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
			devopsLogger.Error(fmt.Sprintf("%s", err))
			return nil, err
		}
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

// Deploy deploys the supplied chaincode image to the validators through a transaction
func (d *Devops) Deploy(ctx context.Context, spec *pb.ChaincodeSpec) (*pb.Response, error) {

	tx, deploymentSpecBytes, sec, err := d.createDeployTransaction(spec)
	if sec != nil {
		defer crypto.CloseClient(sec)
	}
	if err != nil {
		return nil, err
	}

	if devopsLogger.IsEnabledFor(logging.DEBUG) {
		devopsLogger.Debugf("Sending deploy transaction (%s) to validator", tx.Txid)
	}

	encapsTx, err := container.EncapsulateTransactionToInBlock(tx)
	if err != nil {
		return nil, fmt.Errorf("Unable to Encapsulate the transaction: %s", err)
	}
	resp := d.coord.ExecuteTransaction(encapsTx)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	}
	resp.Msg = deploymentSpecBytes

	return resp, err
}

func (d *Devops) createDeployTransaction(spec *pb.ChaincodeSpec) (*pb.Transaction, []byte, crypto.Client, error) {
	// get the deployment spec
	chaincodeDeploymentSpec, err := d.getChaincodeBytes(spec)

	if err != nil {
		devopsLogger.Errorf("Error deploying chaincode spec: %v\n\n error: %s", spec, err)
		return nil, nil, nil, err
	}

	chaincodeDSBytes, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		devopsLogger.Errorf("chaincode deployment spec successfully generated, but unable to serialize it (%s)", err)
	}

	// Now create the Transactions message and send to Peer.

	transID := chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name

	var tx *pb.Transaction
	var sec crypto.Client

	if peer.SecurityEnabled() {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Initializing secure devops using context %s", spec.SecureContext)
		}
		sec, err = crypto.InitClient(spec.SecureContext, nil)

		// remove the security context since we are no longer need it down stream
		spec.SecureContext = ""

		if nil != err {
			return nil, chaincodeDSBytes, sec, err
		}

		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating secure transaction %s", transID)
		}
		tx, err = sec.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID, spec.Attributes...)
		if nil != err {
			return nil, chaincodeDSBytes, sec, err
		}
	} else {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating deployment transaction (%s)", transID)
		}
		tx, err = pb.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID)
		if err != nil {
			return nil, chaincodeDSBytes, sec, fmt.Errorf("Error deploying chaincode: %s ", err)
		}
	}

	return tx, chaincodeDSBytes, sec, nil

}

func (d *Devops) invokeOrQuery(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec, attributes []string, invoke bool) (*pb.Response, error) {

	if chaincodeInvocationSpec.ChaincodeSpec.ChaincodeID.Name == "" {
		return nil, errors.New("name not given for invoke/query")
	}

	// Now create the Transactions message and send to Peer.
	transaction, sec, err := d.createExecTx(chaincodeInvocationSpec, attributes, invoke)
	if sec != nil {
		defer crypto.CloseClient(sec)
	}
	if err != nil {
		return nil, err
	}
	if devopsLogger.IsEnabledFor(logging.DEBUG) {
		devopsLogger.Debugf("Sending invocation transaction (%s) to validator", transaction.Txid)
	}
	encapsTx, err := container.EncapsulateTransactionToInBlock(transaction)
	if err != nil {
		return nil, fmt.Errorf("unable to encapsulate transaction: %s", err)
	}
	resp := d.coord.ExecuteTransaction(encapsTx)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	} else {
		if !invoke && nil != sec && viper.GetBool("security.privacy") {
			if resp.Msg, err = sec.DecryptQueryResult(transaction, resp.Msg); nil != err {
				devopsLogger.Errorf("Failed decrypting query transaction result %s", string(resp.Msg[:]))
				//resp = &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}
			}
		}
	}
	return resp, err
}

func (d *Devops) createExecTx(spec *pb.ChaincodeInvocationSpec, attributes []string, invokeTx bool) (*pb.Transaction, crypto.Client, error) {
	var tx *pb.Transaction
	var uuid string
	var sec crypto.Client
	var err error

	var customIDgenAlg = strings.ToLower(spec.IdGenerationAlg)
	if invokeTx {
		if customIDgenAlg != "" {
			ctorbytes, err := asn1.Marshal(*spec.ChaincodeSpec.CtorMsg)
			if err != nil {
				return nil, nil, fmt.Errorf("Error marshalling constructor: %s", err)
			}
			uuid, err = util.GenerateIDWithAlg(customIDgenAlg, ctorbytes)
			if err != nil {
				return nil, nil, err
			}
		} else {
			uuid = util.GenerateUUID()
		}
	} else {
		uuid = util.GenerateUUID()
	}
	devopsLogger.Infof("Transaction ID: %v", uuid)
	if peer.SecurityEnabled() {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Initializing secure devops using context %s", spec.ChaincodeSpec.SecureContext)
		}
		sec, err = crypto.InitClient(spec.ChaincodeSpec.SecureContext, nil)
		// remove the security context since we are no longer need it down stream
		spec.ChaincodeSpec.SecureContext = ""
		if nil != err {
			return nil, sec, err
		}
	}

	//TODO What should we do with the attributes
	if nil != sec {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating secure invocation transaction %s", uuid)
		}
		if invokeTx {
			tx, err = sec.NewChaincodeExecute(spec, uuid, attributes...)
		} else {
			tx, err = sec.NewChaincodeQuery(spec, uuid, attributes...)
		}
		if nil != err {
			return nil, sec, err
		}
	} else {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating invocation transaction (%s)", uuid)
		}
		var t pb.ChaincodeAction
		if invokeTx {
			t = pb.ChaincodeAction_CHAINCODE_INVOKE
		} else {
			t = pb.ChaincodeAction_CHAINCODE_QUERY
		}
		tx, err = pb.NewChaincodeExecute(spec, uuid, t)
		if nil != err {
			return nil, sec, err
		}
	}
	return tx, sec, nil
}

// checkIfQueryConsistent checks if the setSpecification is a query transaction or a txSet.
// a query transaction is formed by a set that contains only a transaction with Chaincode_Action == DEPLOY
// otherwise a valid set is formed by transactions that have as action either DEPLOY or INVOKE
// returns true if the set is encapsulating a query transaction and false otherwise
// returns an error if the transactions set is not consistent as defined above
func (d *Devops) checkQueryConsistency(txSetSpec *pb.TxSetSpec) (bool, error) {
	numTxInSet := len(txSetSpec.TxSpecs)
	if numTxInSet == 0 {
		return false, errors.New("A transactions set must contain at least one transaction.")
	}
	if len(txSetSpec.TxSpecs) > 1 {
		// Cannot have a txSet with more than one query
		return false, nil
	}
	// Try to unmarshal to a query transaction:
	trans := &pb.TxSpec{}
	err := proto.Unmarshal(txSetSpec.TxSpecs[0], trans)
	if err != nil {
		return false, err
	}
	isQuery := trans.Action == pb.ChaincodeAction_CHAINCODE_QUERY
	return isQuery, nil
}

// Don't need this function anymore, keep it for reference atm
//func (d *Devops) createTxSet(txSetSpec *pb.TxSetSpec) (*pb.TransactionSet, []byte, error) {
//	txSet := &pb.TransactionSet{}
//	txSet.DefaultInx = txSetSpec.DefaultInx
//	var deplBytes []byte
//	for i, txSpec := range txSetSpec.TxSpecs {
//		switch txSpec.Action {
//		case pb.ChaincodeAction_CHAINCODE_DEPLOY:
//			if txSpec.GetCodeSpec() == nil {
//				return nil, deplBytes, fmt.Errorf("Trying to add a Deploy transaction to the tx set without a valid Chaincode Specification.")
//			}
//			tx, deplBytesCurr, sec, err := d.createDeployTransaction(txSpec.GetCodeSpec())
//			if sec != nil {
//				crypto.CloseClient(sec)
//			}
//			if err != nil {
//				return nil, deplBytes, err
//			}
//			if uint64(i) == txSet.DefaultInx {
//				deplBytes = deplBytesCurr
//			}
//			txSet.Transactions = append(txSet.Transactions, tx)
//		case pb.ChaincodeAction_CHAINCODE_INVOKE:
//			if txSpec.GetInvocationSpec() == nil {
//				return nil, deplBytes, fmt.Errorf("Trying to add a Invoke transaction to the tx set without a valid Invocation Specification.")
//			}
//			tx, sec, err := d.createExecTx(txSpec.GetInvocationSpec(), txSpec.GetInvocationSpec().ChaincodeSpec.Attributes, true)
//			if sec != nil {
//				crypto.CloseClient(sec)
//			}
//			if err != nil {
//				return nil, deplBytes, err
//			}
//			txSet.Transactions = append(txSet.Transactions, tx)
//		case pb.ChaincodeAction_CHAINCODE_QUERY:
//			// This should not happen, since checks to exclude query transactions
//			// should have been performed before calling this function
//			return nil, deplBytes, fmt.Errorf("Cannot to create a tx set containing a query transaction")
//		default:
//			return nil, deplBytes, fmt.Errorf("Transaction type not supported to be part of a transactins set. Type: %s", txSpec.Action)
//		}
//	}
//	return txSet, deplBytes, nil
//}

// Invoke performs the supplied invocation on the specified chaincode through a transaction
func (d *Devops) Invoke(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec) (*pb.Response, error) {
	return d.invokeOrQuery(ctx, chaincodeInvocationSpec, chaincodeInvocationSpec.ChaincodeSpec.Attributes, true)
}

// Query performs the supplied query on the specified chaincode through a transaction
func (d *Devops) Query(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec) (*pb.Response, error) {
	return d.invokeOrQuery(ctx, chaincodeInvocationSpec, chaincodeInvocationSpec.ChaincodeSpec.Attributes, false)
}

// IssueTxSet deploys a transactions set or an extension of it in case the set that it refers to was already defined
func (d *Devops) IssueTxSet(ctx context.Context, txSetSpec *pb.TxSetSpec) (*pb.Response, error) {
	isQuery, err := d.checkQueryConsistency(txSetSpec)
	if err != nil {
		return nil, err
	}
	if isQuery {
		// This transactions set is a Query
		// TODO: consider sending a warning saying to call directly query instead of this
		trans := &pb.TxSpec{}
		err := proto.Unmarshal(txSetSpec.TxSpecs[0], trans)
		if err != nil {
			return nil, fmt.Errorf("Set previously verified to be a query transaction, but unable to unmarshal later. %s", err)
		}
		return d.Query(ctx, trans.GetInvocationSpec())
	}
	transSet := &pb.TransactionSet{Transactions: txSetSpec.TxSpecs, DefaultInx: txSetSpec.DefaultInx}

	transSetBytes, err := proto.Marshal(transSet)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal the created txSet. Err: %s", err)
	}
	marshaledTimestamp, err := proto.Marshal(util.CreateUtcTimestamp())
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal current timestamp. Err: %s", err)
	}
	transSetBytes = append(transSetBytes, marshaledTimestamp...)

	inBlockTx := &pb.InBlockTransaction{
		Transaction: 		  &pb.InBlockTransaction_TransactionSet{TransactionSet: transSet},
		Txid:        		  hex.EncodeToString(util.ComputeCryptoHash(transSetBytes)),
		Timestamp:   		  util.CreateUtcTimestamp(),
		Nonce:		 		  txSetSpec.Metadata,
		ConfidentialityLevel: pb.ConfidentialityLevel_CONFIDENTIAL,
	}
	resp := d.coord.ExecuteTransaction(inBlockTx)
	if resp.Status == pb.Response_FAILURE {
		// Right now if the the dafault transaction of the set is reject the set **should** be rejected as well..
		// So returning this error should be fine
		err = fmt.Errorf(string(resp.Msg))
	}
	outerResponse := &pb.Response{
		Status: resp.Status,
		Msg: []byte(inBlockTx.Txid),
		InnerResp: resp,
	}
	return outerResponse, err
}

// Mutate - Modifies the active transaction of a transactions set
func (d *Devops) Mutate(ctx context.Context, mutantSpec *pb.MutantSpec) (*pb.Response, error) {
	mutantTx := &pb.MutantTransaction{
		TxSetID:    mutantSpec.TxSetID,
		TxSetIndex: mutantSpec.Index,
	}

	mutBytes, err := proto.Marshal(mutantTx)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal the mutant transaction (%s)", err)
	}
	marshaledTimestamp, err := proto.Marshal(util.CreateUtcTimestamp())
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal current timestamp. Err: %s", err)
	}
	mutBytes = append(mutBytes, marshaledTimestamp...)


	inBlockTx := &pb.InBlockTransaction{
		Transaction: &pb.InBlockTransaction_MutantTransaction{MutantTransaction: mutantTx},
		Txid:        hex.EncodeToString(util.ComputeCryptoHash(mutBytes)),
		Timestamp:   util.CreateUtcTimestamp(),
	}
	resp := d.coord.ExecuteTransaction(inBlockTx)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	}
	return resp, err
}

func (d *Devops) createTxSetQueryTx(txSetID string) (*pb.InBlockTransaction, error) {

	queryTx := &pb.TxSetStateQuery{
		TxSetID: txSetID,
		Timestamp: util.CreateUtcTimestamp(),
	}

	queryBytes, err := proto.Marshal(queryTx)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal created query tx (%s).", err)
	}

	inBlockTx := &pb.InBlockTransaction{
		Transaction: &pb.InBlockTransaction_SetStQueryTransaction{SetStQueryTransaction: queryTx},
		Txid: hex.EncodeToString(util.ComputeCryptoHash(queryBytes)),
		Timestamp: util.CreateUtcTimestamp(),
	}
	return inBlockTx, nil
}

func (d *Devops) QueryTxSetState(ctx context.Context, querySpec *pb.MutantSpec) (*pb.Response, error) {
	var err error

	if querySpec.TxSetID == "" {
		return nil, errors.New("tx set id not given for query tx set state tx")
	}

	// Now create the Transactions message and send to Peer.
	transaction, err := d.createTxSetQueryTx(querySpec.TxSetID)
	if err != nil {
		return nil, fmt.Errorf("Unable to create tx set state query transaction for tx id: %s, err: %s", querySpec.TxSetID, err)
	}

	if devopsLogger.IsEnabledFor(logging.DEBUG) {
		devopsLogger.Debugf("Sending tx set state query transaction (%s) to validator", transaction.Txid)
	}
	resp := d.coord.ExecuteTransaction(transaction)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	}

	// TODO provide encryption for txSetState transactions

	return resp, err
}

// CheckSpec to see if chaincode resides within current package capture for language.
func CheckSpec(spec *pb.ChaincodeSpec) error {
	// Don't allow nil value
	if spec == nil {
		return errors.New("Expected chaincode specification, nil received")
	}

	platform, err := platforms.Find(spec.Type)
	if err != nil {
		return fmt.Errorf("Failed to determine platform type: %s", err)
	}

	return platform.ValidateSpec(spec)
}

// EXP_GetApplicationTCert retrieves an application TCert for the supplied user
func (d *Devops) EXP_GetApplicationTCert(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	var sec crypto.Client
	var err error

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TCert for id: %s", secret.EnrollId)
		tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		certDER := tcertHandler.GetCertificate()
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: certDER}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
	// TODO: Handle timeout and expiration
}

// EXP_PrepareForTx prepares a binding/TXHandler pair to be used in subsequent TX
func (d *Devops) EXP_PrepareForTx(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	var sec crypto.Client
	var err error
	var txHandler crypto.TransactionHandler
	var binding []byte

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TXHandler for id: %s", secret.EnrollId)
		tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		txHandler, err = tcertHandler.GetTransactionHandler()
		binding, err = txHandler.GetBinding()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		// Now add to binding map
		d.bindingMap.addBinding(binding, txHandler)
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: binding}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
	// TODO: Handle timeout and expiration
}

// EXP_ProduceSigma produces a sigma as []byte and returns in response
func (d *Devops) EXP_ProduceSigma(ctx context.Context, sigmaInput *pb.SigmaInput) (*pb.Response, error) {
	var sec crypto.Client
	var err error
	var sigma []byte
	secret := sigmaInput.Secret

	type RBACMetatdata struct {
		Cert  []byte
		Sigma []byte
	}

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TCertHandler for id: %s, from DER = %s", secret.EnrollId, sigmaInput.AppTCert)
		tcertHandler, err := sec.GetTCertificateHandlerFromDER(sigmaInput.AppTCert)
		//tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(fmt.Errorf("Error getting TCertHandler from DER:  %s", err).Error())}, nil
		}
		tcert := sigmaInput.AppTCert //tcertHandler.GetCertificate()
		sigma, err = tcertHandler.Sign(append(tcert, sigmaInput.Data...))
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(fmt.Errorf("Error signing with TCertHandler from DER:  %s", err).Error())}, nil
		}
		// Produce the SigmaOutput
		asn1Encoding, err := asn1.Marshal(RBACMetatdata{Cert: tcert, Sigma: sigma})
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		sigmaOutput := &pb.SigmaOutput{Tcert: tcert, Sigma: sigma, Asn1Encoding: asn1Encoding}
		sigmaOutputBytes, err := proto.Marshal(sigmaOutput)
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: sigmaOutputBytes}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil

}

// EXP_ExecuteWithBinding executes a transaction with a specific binding/TXHandler
func (d *Devops) EXP_ExecuteWithBinding(ctx context.Context, executeWithBinding *pb.ExecuteWithBinding) (*pb.Response, error) {

	if d.isSecurityEnabled {
		devopsLogger.Debug("Getting TxHandler for binding")

		txHandler, err := d.bindingMap.getTxHandlerForBinding(executeWithBinding.Binding)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		ctorbytes, merr := asn1.Marshal(*executeWithBinding.ChaincodeInvocationSpec.ChaincodeSpec.CtorMsg)
		if merr != nil {
			return nil, fmt.Errorf("Error marshalling constructor: %s", err)
		}
		tid, generr := util.GenerateIDWithAlg("", ctorbytes)
		if generr != nil {
			return nil, fmt.Errorf("Error: cannot generate TX ID (executing with binding). (%s)", generr)
		}

		tx, err := txHandler.NewChaincodeExecute(executeWithBinding.ChaincodeInvocationSpec, tid)
		if err != nil {
			return nil, fmt.Errorf("Error creating executing with binding:  %s", err)
		}

		encapsTx, err := container.EncapsulateTransactionToInBlock(tx)
		if err != nil {
			return nil, fmt.Errorf("Unable to encapsulate transaction: %s", err)
		}

		return d.coord.ExecuteTransaction(encapsTx), nil
		//return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("NOT IMPLEMENTED")}, nil

		//return &pb.Response{Status: pb.Response_SUCCESS, Msg: sigmaOutputBytes}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
}
