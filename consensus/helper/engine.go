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

package helper

import (
	"github.com/hyperledger/fabric/consensus"
	"github.com/hyperledger/fabric/core/peer"

	"fmt"
	"sync"

	"github.com/hyperledger/fabric/consensus/controller"
	"github.com/hyperledger/fabric/consensus/util"
	"github.com/hyperledger/fabric/core/chaincode"
	pb "github.com/hyperledger/fabric/protos"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/proto"
)

// EngineImpl implements a struct to hold consensus.Consenter, PeerEndpoint and MessageFan
type EngineImpl struct {
	consenter    consensus.Consenter
	helper       *Helper
	peerEndpoint *pb.PeerEndpoint
	consensusFan *util.MessageFan
}

// GetHandlerFactory returns new NewConsensusHandler
func (eng *EngineImpl) GetHandlerFactory() peer.HandlerFactory {
	return NewConsensusHandler
}

// ProcessTransactionMsg processes a Message in context of a Transaction
func (eng *EngineImpl) ProcessTransactionMsg(msg *pb.Message, inBlockTx *pb.InBlockTransaction) (response *pb.Response) {
	switch tx := inBlockTx.Transaction.(type) {
	case *pb.InBlockTransaction_TransactionSet, *pb.InBlockTransaction_SetStQueryTransaction:

		// Make sure that if this is a Transactions Set it is encapsulating a query.
		if txSet, ok := tx.(*pb.InBlockTransaction_TransactionSet); ok {
			if len(txSet.TransactionSet.Transactions) != 1 {
				break
			}
			transaction := &pb.Transaction{}
			err := proto.Unmarshal(txSet.TransactionSet.Transactions[0], transaction)
			if err != nil {
				logger.Infof("Error unmarshaling, probably it was not a query transaction, so ignoring it here. Err: [%s]", err)
				break
			}
			if transaction.Type != pb.ChaincodeAction_CHAINCODE_QUERY {
				break
			}
		}

		// Check if this is a query transaction. A TxSet is a query tx if it contains only one transaction and it is of type Query.
		//TODO: Do we always verify security, or can we supply a flag on the invoke ot this functions so to bypass check for locally generated transactions?
		if !engine.helper.valid {
			logger.Warning("Rejecting query because state is currently not valid")
			return &pb.Response{Status: pb.Response_FAILURE,
				Msg: []byte("Error: state may be inconsistent, cannot query")}
		}

		// The secHelper is set during creat ChaincodeSupport, so we don't need this step
		// cxt := context.WithValue(context.Background(), "security", secHelper)
		cxt := context.Background()
		//query will ignore events as these are not stored on ledger (and query can report
		//"event" data synchronously anyway)
		result, _, err := chaincode.Execute(cxt, chaincode.GetChain(chaincode.DefaultChain), inBlockTx)
		if err != nil {
			response = &pb.Response{Status: pb.Response_FAILURE,
				Msg: []byte(fmt.Sprintf("Error:%s", err))}
		} else {
			response = &pb.Response{Status: pb.Response_SUCCESS, Msg: result}
		}
		return response
	}

	// Chaincode Transaction
	response = &pb.Response{Status: pb.Response_SUCCESS, Msg: []byte(inBlockTx.Txid)}

	//TODO: Do we need to verify security, or can we supply a flag on the invoke ot this functions
	// If we fail to marshal or verify the tx, don't send it to consensus plugin
	if response.Status == pb.Response_FAILURE {
		return response
	}

	// Pass the message to the consenter (eg. PBFT) NOTE: Make sure engine has been initialized
	if eng.consenter == nil {
		return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Engine not initialized")}
	}
	// TODO, do we want to put these requests into a queue? This will block until
	// the consenter gets around to handling the message, but it also provides some
	// natural feedback to the REST API to determine how long it takes to queue messages
	err := eng.consenter.RecvMsg(msg, eng.peerEndpoint.ID)
	if err != nil {
		response = &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}
	}

	return response
}

func (eng *EngineImpl) setConsenter(consenter consensus.Consenter) *EngineImpl {
	eng.consenter = consenter
	return eng
}

func (eng *EngineImpl) setPeerEndpoint(peerEndpoint *pb.PeerEndpoint) *EngineImpl {
	eng.peerEndpoint = peerEndpoint
	return eng
}

var engineOnce sync.Once

var engine *EngineImpl

func getEngineImpl() *EngineImpl {
	return engine
}

// GetEngine returns initialized peer.Engine
func GetEngine(coord peer.MessageHandlerCoordinator) (peer.Engine, error) {
	var err error
	engineOnce.Do(func() {
		engine = new(EngineImpl)
		engine.helper = NewHelper(coord)
		engine.consenter = controller.NewConsenter(engine.helper)
		engine.helper.setConsenter(engine.consenter)
		engine.peerEndpoint, err = coord.GetPeerEndpoint()
		engine.consensusFan = util.NewMessageFan()

		go func() {
			logger.Debug("Starting up message thread for consenter")

			// The channel never closes, so this should never break
			for msg := range engine.consensusFan.GetOutChannel() {
				engine.consenter.RecvMsg(msg.Msg, msg.Sender)
			}
		}()
	})
	return engine, err
}
