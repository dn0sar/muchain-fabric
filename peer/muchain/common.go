package muchain

import (
	"fmt"
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/peer/util"
	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"
	"crypto/ecdsa"
)

func parseFile(path string) (*pb.TxSetInput, error) {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read %s. Error: %s", path, err.Error())
	}

	var txSetInput = &pb.TxSetInput{}
	err = json.Unmarshal(fileBytes, &txSetInput)
	if err != nil {
		return nil, fmt.Errorf("Muchain argument error: %s", err)
	}

	return txSetInput, nil
}

func createTxSpecArray(simpSpecArr []*pb.TxSetInput_SimplifiedSpec, defIndex uint64) ([][]byte, *pb.TxSpec, error) {
	var defSpec *pb.TxSpec
	var txSetSpecArr = make([][]byte, len(simpSpecArr))
	for i, simpSpec := range simpSpecArr {
		var txSpec = &pb.TxSpec{}
		txSpec.Action = simpSpec.Action
		spec := &pb.ChaincodeSpec{
			Type:        simpSpec.Lang,
			ChaincodeID: simpSpec.ChaincodeID,
			CtorMsg:     simpSpec.InputArgs,
		}
		spec, err := common.SetSecurityParams(fabricUsr, spec)
		if err != nil {
			return txSetSpecArr, defSpec, fmt.Errorf("Unable to set security for one of the transactions of the set: %s", err)
		}
		if simpSpec.Action == pb.ChaincodeAction_CHAINCODE_DEPLOY {
			txSpec.Spec = &pb.TxSpec_CodeSpec{CodeSpec: spec}
		} else {
			invocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
			if simpSpec.CustomIDGen != "" {
				invocationSpec.IdGenerationAlg = simpSpec.CustomIDGen
			}
			txSpec.Spec = &pb.TxSpec_InvocationSpec{InvocationSpec: invocationSpec}
		}
		if uint64(i) == defIndex {
			defSpec = txSpec
		}
		marshaledSpec, err := proto.Marshal(txSpec)
		if err != nil {
			return txSetSpecArr, defSpec, fmt.Errorf("Unable to marshal generated txSetSpecification: %s", err)
		}
		txSetSpecArr[i] = marshaledSpec
	}
	return txSetSpecArr, defSpec, nil
}

func encryptNonce(nonce []byte) ([]byte, error) {
	localStore := util.GetCliFilePath()
	logger.Infof("Local data store for client loginToken: %s", localStore)
	pem, err := ioutil.ReadFile(localStore + "chainpub_" + fabricUsr)
	if err != nil {
		return nil, fmt.Errorf("Error when reading the chain public key: %s\n", err)
	}
	eciesSPI := ecies.NewSPI()
	pubTemp, err := primitives.PEMtoPublicKey(pem, nil)
	if err != nil {
		return nil, fmt.Errorf("Error when reading the chain public key: %s\n", err)
	}
	pubKey, err := eciesSPI.NewPublicKey(nil, pubTemp.(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("Error when converting the chain public key: %s\n", err)
	}
	cipher, err := eciesSPI.NewAsymmetricCipherFromPublicKey(pubKey)
	if err != nil {
		logger.Errorf("Failed creating new encryption scheme: [%s]", err)
		return nil, err
	}

	nonce, err = cipher.Process(nonce)
	if err != nil {
		logger.Errorf("Failed encrypting the nonce: [%s]", err)
		return nil, err
	}
	return nonce, nil
}

