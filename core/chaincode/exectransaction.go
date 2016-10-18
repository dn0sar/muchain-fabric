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

package chaincode

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/events/producer"
	pb "github.com/hyperledger/fabric/protos"
)

//Execute - execute the default transaction of a transaction set (which might also be a query transaction) or a mutable transaction
func Execute(ctxt context.Context, chain *ChaincodeSupport, inBlockTx *pb.InBlockTransaction) ([]byte, *pb.ChaincodeEvent, error) {
	var err error
	//TODO: Check if the same transaction set was already part of the block
	// get a handle to ledger to mark the begin/finish of a tx
	ledger, ledgerErr := ledger.GetLedger()
	if ledgerErr != nil {
		return nil, nil, fmt.Errorf("Failed to get handle to ledger (%s)", ledgerErr)
	}

	if secHelper := chain.getSecHelper(); nil != secHelper {
		var err error
		inBlockTx, err = secHelper.TransactionPreExecution(inBlockTx)
		// Note that inBlockTx is now decrypted and is a deep clone of the original input inBlockTx
		if nil != err {
			return nil, nil, err
		}
	}

	nextBlockNr := ledger.GetBlockchainSize()

	switch tx := inBlockTx.Transaction.(type) {
	case *pb.InBlockTransaction_TransactionSet:
		// Extend the set here and terminate the inBlockTransaction
		var txSetExistedAlready = true
		ledger.TxBegin(inBlockTx.Txid)
		txSetStValue, err := ledger.GetTxSetState(inBlockTx.Txid, true)
		if err != nil {
			ledger.TxFinished(inBlockTx.Txid, false)
			return nil, nil, fmt.Errorf("Failed to retrieve the txSet state, txID: %s, err: %s.", inBlockTx.Txid, err)
		}
		if txSetStValue == nil {
			txSetExistedAlready = false
			txSetStValue = &pb.TxSetStateValue{}
			txSetStValue.Index = &pb.TxSetIndex{BlockNr: nextBlockNr, InBlockIndex: tx.TransactionSet.DefaultInx}
		}
		txSetStValue.Nonce++
		txInSet := uint64(len(tx.TransactionSet.Transactions))
		txSetStValue.TxNumber += txInSet
		txSetStValue.TxsInBlock[nextBlockNr] = txInSet
		ledger.SetTxSetState(inBlockTx.Txid, txSetStValue)
		ledger.TxFinished(inBlockTx.Txid, true)

		if txSetExistedAlready {
			// The default transaction did not change, hence there is no need to execute the default transaction
			return nil, nil, err
		}

		if txSetStValue.Index.BlockNr != nextBlockNr {
			// The default transaction is not the one of this block
			// do not execute it
			return nil, nil, err
		}
		t := tx.TransactionSet.Transactions[txSetStValue.Index.InBlockIndex]
		if t.Type == pb.ChaincodeAction_CHAINCODE_DEPLOY {
			_, err := chain.Deploy(ctxt, t)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to deploy chaincode spec(%s)", err)
			}

			//launch and wait for ready
			markTxBegin(ledger, t)
			_, _, err = chain.Launch(ctxt, t)
			if err != nil {
				markTxFinish(ledger, t, false)
				return nil, nil, fmt.Errorf("%s", err)
			}
			markTxFinish(ledger, t, true)
		} else if t.Type == pb.ChaincodeAction_CHAINCODE_INVOKE || t.Type == pb.ChaincodeAction_CHAINCODE_QUERY {
			//will launch if necessary (and wait for ready)
			cID, cMsg, err := chain.Launch(ctxt, t)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to launch chaincode spec(%s)", err)
			}

			//this should work because it worked above...
			chaincode := cID.Name

			if err != nil {
				return nil, nil, fmt.Errorf("Failed to stablish stream to container %s", chaincode)
			}

			// TODO: Need to comment next line and uncomment call to getTimeout, when transaction blocks are being created
			timeout := time.Duration(30000) * time.Millisecond
			//timeout, err := getTimeout(cID)

			if err != nil {
				return nil, nil, fmt.Errorf("Failed to retrieve chaincode spec(%s)", err)
			}

			var ccMsg *pb.ChaincodeMessage
			if t.Type == pb.ChaincodeAction_CHAINCODE_INVOKE {
				ccMsg, err = createTransactionMessage(t.Txid, cMsg)
				if err != nil {
					return nil, nil, fmt.Errorf("Failed to transaction message(%s)", err)
				}
			} else {
				ccMsg, err = createQueryMessage(t.Txid, cMsg)
				if err != nil {
					return nil, nil, fmt.Errorf("Failed to query message(%s)", err)
				}
			}

			markTxBegin(ledger, t)
			resp, err := chain.Execute(ctxt, chaincode, ccMsg, timeout, t)
			if err != nil {
				// Rollback transaction
				markTxFinish(ledger, t, false)
				return nil, nil, fmt.Errorf("Failed to execute transaction or query(%s)", err)
			} else if resp == nil {
				// Rollback transaction
				markTxFinish(ledger, t, false)
				return nil, nil, fmt.Errorf("Failed to receive a response for (%s)", t.Txid)
			} else {
				if resp.ChaincodeEvent != nil {
					resp.ChaincodeEvent.ChaincodeID = chaincode
					resp.ChaincodeEvent.TxID = t.Txid
				}

				if resp.Type == pb.ChaincodeMessage_COMPLETED || resp.Type == pb.ChaincodeMessage_QUERY_COMPLETED {
					// Success
					markTxFinish(ledger, t, true)
					return resp.Payload, resp.ChaincodeEvent, nil
				} else if resp.Type == pb.ChaincodeMessage_ERROR || resp.Type == pb.ChaincodeMessage_QUERY_ERROR {
					// Rollback transaction
					markTxFinish(ledger, t, false)
					return nil, resp.ChaincodeEvent, fmt.Errorf("Transaction or query returned with failure: %s", string(resp.Payload))
				}
				markTxFinish(ledger, t, false)
				return resp.Payload, nil, fmt.Errorf("receive a response for (%s) but in invalid state(%d)", t.Txid, resp.Type)
			}

		} else {
			err = fmt.Errorf("Invalid transaction type %s", t.Type.String())
		}
		return nil, nil, err
	case *pb.InBlockTransaction_MutantTransaction:
		// TODO: Trigger chaincode state re-computation here.
		ledger.TxBegin(tx.MutantTransaction.TxSetID)
		txSetStValue, err := ledger.GetTxSetState(tx.MutantTransaction.TxSetID, true)
		if err != nil {
			ledger.TxFinished(tx.MutantTransaction.TxSetID, false)
			return nil, nil, fmt.Errorf("Failed to retrieve the txSet state, txID: %s, err: %s.", inBlockTx.Txid, err)
		}
		if txSetStValue == nil {
			ledger.TxFinished(tx.MutantTransaction.TxSetID, false)
			return nil, nil, fmt.Errorf("Issuing a mutant transaction for an inexisted tx set id.")
		}
		txSetStValue.Nonce++
		txSetStValue.Index = tx.MutantTransaction.TxSetIndex
		ledger.SetTxSetState(tx.MutantTransaction.TxSetID, txSetStValue)
		ledger.TxFinished(tx.MutantTransaction.TxSetID, true)
		return nil, nil, err
	}
	return nil, nil, err
}

//ExecuteTransactions - will execute transactions on the array one by one
//will return an array of errors one for each transaction. If the execution
//succeeded, array element will be nil. returns []byte of state hash or
//error
func ExecuteTransactions(ctxt context.Context, cname ChainName, xacts []*pb.InBlockTransaction) (succeededTXs []*pb.InBlockTransaction, stateHash []byte, ccevents []*pb.ChaincodeEvent, txerrs []error, err error) {
	var chain = GetChain(cname)
	if chain == nil {
		// TODO: We should never get here, but otherwise a good reminder to better handle
		panic(fmt.Sprintf("[ExecuteTransactions]Chain %s not found\n", cname))
	}

	txerrs = make([]error, len(xacts))
	ccevents = make([]*pb.ChaincodeEvent, len(xacts))
	var succeededTxs = make([]*pb.InBlockTransaction, 0)
	for i, t := range xacts {
		_, ccevents[i], txerrs[i] = Execute(ctxt, chain, t)
		if txerrs[i] == nil {
			succeededTxs = append(succeededTxs, t)
		} else {
			sendTxRejectedEvent(xacts[i], txerrs[i].Error())
		}
	}

	var lgr *ledger.Ledger
	lgr, err = ledger.GetLedger()
	if err == nil {
		stateHash, err = lgr.GetTempStateHash()
	}

	return succeededTxs, stateHash, ccevents, txerrs, err
}

// GetSecureContext returns the security context from the context object or error
// Security context is nil if security is off from core.yaml file
// func GetSecureContext(ctxt context.Context) (crypto.Peer, error) {
// 	var err error
// 	temp := ctxt.Value("security")
// 	if nil != temp {
// 		if secCxt, ok := temp.(crypto.Peer); ok {
// 			return secCxt, nil
// 		}
// 		err = errors.New("Failed to convert security context type")
// 	}
// 	return nil, err
// }

var errFailedToGetChainCodeSpecForTransaction = errors.New("Failed to get ChainCodeSpec from Transaction")

func getTimeout(cID *pb.ChaincodeID) (time.Duration, error) {
	ledger, err := ledger.GetLedger()
	if err == nil {
		chaincodeID := cID.Name
		txID, err := ledger.GetState(chaincodeID, "github.com_openblockchain_obc-peer_chaincode_id", true)
		if err == nil {
			transSet, err := ledger.GetTransactionByID(string(txID))
			if err == nil && transSet != nil && transSet.GetTransactionSet() != nil {
				// TODO: get the current default transaction here instead
				tx := transSet.GetTransactionSet().Transactions[transSet.GetTransactionSet().DefaultInx]
				chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{}
				proto.Unmarshal(tx.Payload, chaincodeDeploymentSpec)
				chaincodeSpec := chaincodeDeploymentSpec.GetChaincodeSpec()
				timeout := time.Duration(time.Duration(chaincodeSpec.Timeout) * time.Millisecond)
				return timeout, nil
			}
		}
	}

	return -1, errFailedToGetChainCodeSpecForTransaction
}

func markTxBegin(ledger *ledger.Ledger, t *pb.Transaction) {
	if t.Type == pb.ChaincodeAction_CHAINCODE_QUERY {
		return
	}
	ledger.TxBegin(t.Txid)
}

func markTxFinish(ledger *ledger.Ledger, t *pb.Transaction, successful bool) {
	if t.Type == pb.ChaincodeAction_CHAINCODE_QUERY {
		return
	}
	ledger.TxFinished(t.Txid, successful)
}

func sendTxRejectedEvent(tx *pb.InBlockTransaction, errorMsg string) {
	producer.Send(producer.CreateRejectionEvent(tx, errorMsg))
}
