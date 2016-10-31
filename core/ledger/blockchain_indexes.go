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

package ledger

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
	"github.com/tecbot/gorocksdb"
)

var indexLogger = logging.MustGetLogger("indexes")
var prefixBlockHashKey = byte(1)
var prefixTxIDKey = byte(2)
var prefixAddressBlockNumCompositeKey = byte(3)

type blockchainIndexer interface {
	isSynchronous() bool
	start(blockchain *blockchain) error
	createIndexes(block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error
	fetchBlockNumberByBlockHash(blockHash []byte) (uint64, error)
	fetchTransactionIndexByID(txID string) (uint64, uint64, error)
	fetchTransactionIndexMap(txID string) (map[uint64]uint64, error)
	stop()
}

// Implementation for sync indexer
type blockchainIndexerSync struct {
}

func newBlockchainIndexerSync() *blockchainIndexerSync {
	return &blockchainIndexerSync{}
}

func (indexer *blockchainIndexerSync) isSynchronous() bool {
	return true
}

func (indexer *blockchainIndexerSync) start(blockchain *blockchain) error {
	return nil
}

func (indexer *blockchainIndexerSync) createIndexes(
	block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error {
	return addIndexDataForPersistence(block, blockNumber, blockHash, writeBatch)
}

func (indexer *blockchainIndexerSync) fetchBlockNumberByBlockHash(blockHash []byte) (uint64, error) {
	return fetchBlockNumberByBlockHashFromDB(blockHash)
}

func (indexer *blockchainIndexerSync) fetchTransactionIndexByID(txID string) (uint64, uint64, error) {
	mapping, err := fetchTransactionIndexByIDFromDB(txID)
	if err != nil {
		return 0, 0, err
	}
	// Return any mapping from the map (usually there is only one mapping, except for sets, but this method should not be called for sets.)
	for block, index := range mapping.IndexInBlock {
		return block, index, nil
	}
	return 0, 0, newLedgerError(ErrorTypeOutOfBounds, fmt.Sprintf("No indexes stored for the queried txid [%x]", txID))
}

func (indexer *blockchainIndexerSync) fetchTransactionIndexMap(txID string) (map[uint64]uint64, error) {
	mapping, err := fetchTransactionIndexByIDFromDB(txID)
	if err != nil {
		return nil,  newLedgerError(ErrorTypeResourceNotFound, fmt.Sprintf("Unable to retrieve the index map from the db [%x]", err))
	}
	return mapping.IndexInBlock, nil
}


func (indexer *blockchainIndexerSync) stop() {
	return
}

// Try to retrieve a map for a given txID
func getTransactionBlockIndexMap(txID string) (*protos.TxSetToBlock, error) {
	blockNumTxIndexBytes, err := db.GetDBHandle().GetFromIndexesCF(encodeTxIDKey(txID))
	if err != nil {
		return nil, err
	}
	blockMap := &protos.TxSetToBlock{}
	err = proto.Unmarshal(blockNumTxIndexBytes, blockMap)
	if blockMap.IndexInBlock == nil {
		blockMap.IndexInBlock = make(map[uint64]uint64)
	}
	return blockMap, err
}

// Functions for persisting and retrieving index data
func addIndexDataForPersistence(block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error {
	openchainDB := db.GetDBHandle()
	cf := openchainDB.IndexesCF
	var err error

	// add blockhash -> blockNumber
	indexLogger.Debugf("Indexing block number [%d] by hash = [%x]", blockNumber, blockHash)
	writeBatch.PutCF(cf, encodeBlockHashKey(blockHash), encodeBlockNumber(blockNumber))

	addressToTxIndexesMap := make(map[string][]uint64)
	addressToChaincodeIDsMap := make(map[string][]*protos.ChaincodeID)

	transactions := block.GetTransactions()
	for txIndex, inBlockTx := range transactions {
		txBlockIndex, err := getTransactionBlockIndexMap(inBlockTx.Txid)
		if err != nil {
			ledgerLogger.Errorf("Unable to get previous info for block allocation of TxID: %s. Err = %s", inBlockTx.Txid, err)
			// Continue and ignore this error.
		}
		txBlockIndex.IndexInBlock[blockNumber] = uint64(txIndex)
		bytes, err := proto.Marshal(txBlockIndex)
		if err == nil {
			writeBatch.PutCF(cf, encodeTxIDKey(inBlockTx.Txid), bytes)
		} else {
			ledgerLogger.Errorf("Unable to marshal new mapping to blocks for txID: %s. Err = %s", inBlockTx.Txid, err)
		}

		txExecutingAddress := getTxExecutingAddress(inBlockTx)
		addressToTxIndexesMap[txExecutingAddress] = append(addressToTxIndexesMap[txExecutingAddress], uint64(txIndex))
		//REVIEW: this should be executed when I'm creating a block, hence I should take the first default transaction
		switch inBlockTx.Transaction.(type) {
		case *protos.InBlockTransaction_TransactionSet:
			defaultTx, errInt := ledger.GetCurrentDefault(inBlockTx, false)
			err = errInt
			switch defaultTx.Type {
			case protos.ChaincodeAction_CHAINCODE_DEPLOY, protos.ChaincodeAction_CHAINCODE_INVOKE:
				authroizedAddresses, chaincodeID := getAuthorisedAddresses(defaultTx)
				for _, authroizedAddress := range authroizedAddresses {
					addressToChaincodeIDsMap[authroizedAddress] = append(addressToChaincodeIDsMap[authroizedAddress], chaincodeID)
				}
			}
		case *protos.InBlockTransaction_MutantTransaction:
			//Skipping this, there is really no need in indexing the mutant transactions since all the relevant info can be retrieved
			// from the Tx Set State
		}
	}
	for address, txsIndexes := range addressToTxIndexesMap {
		writeBatch.PutCF(cf, encodeAddressBlockNumCompositeKey(address, blockNumber), encodeListTxIndexes(txsIndexes))
	}
	return err
}

func fetchBlockNumberByBlockHashFromDB(blockHash []byte) (uint64, error) {
	indexLogger.Debugf("fetchBlockNumberByBlockHashFromDB() for blockhash [%x]", blockHash)
	blockNumberBytes, err := db.GetDBHandle().GetFromIndexesCF(encodeBlockHashKey(blockHash))
	if err != nil {
		return 0, err
	}
	indexLogger.Debugf("blockNumberBytes for blockhash [%x] is [%x]", blockHash, blockNumberBytes)
	if len(blockNumberBytes) == 0 {
		return 0, newLedgerError(ErrorTypeBlockNotFound, fmt.Sprintf("No block indexed with block hash [%x]", blockHash))
	}
	blockNumber := decodeBlockNumber(blockNumberBytes)
	return blockNumber, nil
}

func fetchTransactionIndexByIDFromDB(txID string) (*protos.TxSetToBlock, error) {
	blockNumTxIndexBytes, err := db.GetDBHandle().GetFromIndexesCF(encodeTxIDKey(txID))
	if err != nil {
		return nil, err
	}
	if blockNumTxIndexBytes == nil {
		return nil, ErrResourceNotFound
	}
	decodedVal := &protos.TxSetToBlock{}
	err = proto.Unmarshal(blockNumTxIndexBytes, decodedVal)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal block mapping. (%s)", err)
	}
	return decodedVal, nil
}

func deleteTransactionIndex(txID string) error {
	dbHandle := db.GetDBHandle()
	return dbHandle.Delete(dbHandle.IndexesCF, encodeTxIDKey(txID))
}

func getTxExecutingAddress(tx *protos.InBlockTransaction) string {
	// TODO Fetch address form tx
	return "address1"
}

func getAuthorisedAddresses(tx *protos.Transaction) ([]string, *protos.ChaincodeID) {
	// TODO fetch address from chaincode deployment tx
	// TODO this method should also return error
	data := tx.ChaincodeID
	cID := &protos.ChaincodeID{}
	err := proto.Unmarshal(data, cID)
	if err != nil {
		return nil, nil
	}
	return []string{"address1", "address2"}, cID
}

// functions for encoding/decoding db keys/values for index data
// encode / decode BlockNumber
func encodeBlockNumber(blockNumber uint64) []byte {
	return proto.EncodeVarint(blockNumber)
}

func decodeBlockNumber(blockNumberBytes []byte) (blockNumber uint64) {
	blockNumber, _ = proto.DecodeVarint(blockNumberBytes)
	return
}

// encode / decode BlockNumTxIndex
func encodeBlockNumTxIndex(blockNumber uint64, txIndexInBlock uint64) []byte {
	b := proto.NewBuffer([]byte{})
	b.EncodeVarint(blockNumber)
	b.EncodeVarint(txIndexInBlock)
	return b.Bytes()
}

func decodeBlockNumTxIndex(bytes []byte) (blockNum uint64, txIndex uint64, err error) {
	b := proto.NewBuffer(bytes)
	blockNum, err = b.DecodeVarint()
	if err != nil {
		return
	}
	txIndex, err = b.DecodeVarint()
	if err != nil {
		return
	}
	return
}

// encode BlockHashKey
func encodeBlockHashKey(blockHash []byte) []byte {
	return prependKeyPrefix(prefixBlockHashKey, blockHash)
}

// encode TxIDKey
func encodeTxIDKey(txID string) []byte {
	return prependKeyPrefix(prefixTxIDKey, []byte(txID))
}

func encodeAddressBlockNumCompositeKey(address string, blockNumber uint64) []byte {
	b := proto.NewBuffer([]byte{prefixAddressBlockNumCompositeKey})
	b.EncodeRawBytes([]byte(address))
	b.EncodeVarint(blockNumber)
	return b.Bytes()
}

func encodeListTxIndexes(listTx []uint64) []byte {
	b := proto.NewBuffer([]byte{})
	for i := range listTx {
		b.EncodeVarint(listTx[i])
	}
	return b.Bytes()
}

func prependKeyPrefix(prefix byte, key []byte) []byte {
	modifiedKey := []byte{}
	modifiedKey = append(modifiedKey, prefix)
	modifiedKey = append(modifiedKey, key...)
	return modifiedKey
}
