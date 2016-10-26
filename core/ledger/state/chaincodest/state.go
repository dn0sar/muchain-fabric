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

package chaincodest

import (
	"fmt"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state"
	"github.com/hyperledger/fabric/core/ledger/state/chaincodest/buckettree"
	"github.com/hyperledger/fabric/core/ledger/state/chaincodest/raw"
	"github.com/hyperledger/fabric/core/ledger/state/chaincodest/statemgmt"
	"github.com/hyperledger/fabric/core/ledger/state/chaincodest/trie"
	"github.com/op/go-logging"
	"github.com/tecbot/gorocksdb"
)

var logger = logging.MustGetLogger("state")

var stateImpl statemgmt.HashableState

type stateImplType struct {
	name string
}

func (implInt *stateImplType) Name() string {
	return implInt.name
}

var (
	buckettreeType = &stateImplType{"buckettree"}
	trieType       = &stateImplType{"trie"}
	rawType        = &stateImplType{"raw"}
)

var defaultStateImpl = buckettreeType

// State structure for maintaining world state.
// This encapsulates a particular implementation for managing the state persistence
// This is not thread safe
type State struct {
	stateImpl             statemgmt.HashableState
	stateDelta            *statemgmt.StateDelta
	currentTxStateDelta   *statemgmt.StateDelta
	currentTxID           string
	txStateDeltaHash      map[string][]byte
	updateStateImpl       bool
	historyStateDeltaSize uint64
}

// NewState constructs a new State. This Initializes encapsulated state implementation
func NewState() *State {
	confData := stcomm.GetConfig("state", defaultStateImpl, buckettreeType, trieType, rawType)
	logger.Infof("Initializing state implementation [%s]", confData.StateImplName)
	switch confData.StateImplName {
	case buckettreeType.Name():
		stateImpl = buckettree.NewStateImpl()
	case trieType.Name():
		stateImpl = trie.NewStateImpl()
	case rawType.Name():
		stateImpl = raw.NewStateImpl()
	default:
		panic("Should not reach here. Configs should have checked for the stateImplName being a valid names ")
	}
	err := stateImpl.Initialize(confData.StateImplConfigs)
	if err != nil {
		panic(fmt.Errorf("Error during initialization of state implementation: %s", err))
	}
	return &State{stateImpl, statemgmt.NewStateDelta(), statemgmt.NewStateDelta(), "", make(map[string][]byte),
		false, uint64(confData.DeltaHistorySize)}
}

// TxBegin marks begin of a new tx. If a tx is already in progress, this call panics
func (state *State) TxBegin(txID string) {
	logger.Debugf("txBegin() for txId [%s]", txID)
	if state.txInProgress() {
		panic(fmt.Errorf("A tx [%s] is already in progress. Received call for begin of another tx [%s]", state.currentTxID, txID))
	}
	state.currentTxID = txID
}

// TxFinish marks the completion of on-going tx. If txID is not same as of the on-going tx, this call panics
func (state *State) TxFinish(txID string, txSuccessful bool) {
	logger.Debugf("txFinish() for txId [%s], txSuccessful=[%t]", txID, txSuccessful)
	if state.currentTxID != txID {
		panic(fmt.Errorf("Different txId in tx-begin [%s] and tx-finish [%s]", state.currentTxID, txID))
	}
	if txSuccessful {
		if !state.currentTxStateDelta.IsEmpty() {
			logger.Debugf("txFinish() for txId [%s] merging state changes", txID)
			state.stateDelta.ApplyChanges(state.currentTxStateDelta)
			state.txStateDeltaHash[txID] = state.currentTxStateDelta.ComputeCryptoHash()
			state.updateStateImpl = true
		} else {
			state.txStateDeltaHash[txID] = nil
		}
	}
	state.currentTxStateDelta = statemgmt.NewStateDelta()
	state.currentTxID = ""
}

func (state *State) txInProgress() bool {
	return state.currentTxID != ""
}

// Get returns state for chaincodeID and key. If committed is false, this first looks in memory and if missing,
// pulls from db. If committed is true, this pulls from the db only.
func (state *State) Get(chaincodeID string, key string, committed bool) ([]byte, error) {
	if !committed {
		valueHolder := state.currentTxStateDelta.Get(chaincodeID, key)
		if valueHolder != nil {
			return valueHolder.GetValue(), nil
		}
		valueHolder = state.stateDelta.Get(chaincodeID, key)
		if valueHolder != nil {
			return valueHolder.GetValue(), nil
		}
	}
	return state.stateImpl.Get(chaincodeID, key)
}

// GetRangeScanIterator returns an iterator to get all the keys (and values) between startKey and endKey
// (assuming lexical order of the keys) for a chaincodeID.
func (state *State) GetRangeScanIterator(chaincodeID string, startKey string, endKey string, committed bool) (stcomm.RangeScanIterator, error) {
	stateImplItr, err := state.stateImpl.GetRangeScanIterator(chaincodeID, startKey, endKey)
	if err != nil {
		return nil, err
	}

	if committed {
		return stateImplItr, nil
	}
	return newCompositeRangeScanIterator(
		statemgmt.NewStateDeltaRangeScanIterator(state.currentTxStateDelta, chaincodeID, startKey, endKey),
		statemgmt.NewStateDeltaRangeScanIterator(state.stateDelta, chaincodeID, startKey, endKey),
		stateImplItr), nil
}

// Set sets state to given value for chaincodeID and key. Does not immediately writes to DB
func (state *State) Set(chaincodeID string, key string, value []byte) error {
	logger.Debugf("set() chaincodeID=[%s], key=[%s], value=[%#v]", chaincodeID, key, value)
	if !state.txInProgress() {
		panic("State can be changed only in context of a tx.")
	}

	// Check if a previous value is already set in the state delta
	if state.currentTxStateDelta.IsUpdatedValueSet(chaincodeID, key) {
		// No need to bother looking up the previous value as we will not
		// set it again. Just pass nil
		state.currentTxStateDelta.Set(chaincodeID, key, value, nil)
	} else {
		// Need to lookup the previous value
		previousValue, err := state.Get(chaincodeID, key, true)
		if err != nil {
			return err
		}
		state.currentTxStateDelta.Set(chaincodeID, key, value, previousValue)
	}

	return nil
}

// Delete tracks the deletion of state for chaincodeID and key. Does not immediately writes to DB
func (state *State) Delete(chaincodeID string, key string) error {
	logger.Debugf("delete() chaincodeID=[%s], key=[%s]", chaincodeID, key)
	if !state.txInProgress() {
		panic("State can be changed only in context of a tx.")
	}

	// Check if a previous value is already set in the state delta
	if state.currentTxStateDelta.IsUpdatedValueSet(chaincodeID, key) {
		// No need to bother looking up the previous value as we will not
		// set it again. Just pass nil
		state.currentTxStateDelta.Delete(chaincodeID, key, nil)
	} else {
		// Need to lookup the previous value
		previousValue, err := state.Get(chaincodeID, key, true)
		if err != nil {
			return err
		}
		state.currentTxStateDelta.Delete(chaincodeID, key, previousValue)
	}

	return nil
}

// CopyState copies all the key-values from sourceChaincodeID to destChaincodeID
func (state *State) CopyState(sourceChaincodeID string, destChaincodeID string) error {
	itr, err := state.GetRangeScanIterator(sourceChaincodeID, "", "", true)
	defer itr.Close()
	if err != nil {
		return err
	}
	for itr.Next() {
		k, v := itr.GetKeyValue()
		err := state.Set(destChaincodeID, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetMultipleKeys returns the values for the multiple keys.
func (state *State) GetMultipleKeys(chaincodeID string, keys []string, committed bool) ([][]byte, error) {
	var values [][]byte
	for _, k := range keys {
		v, err := state.Get(chaincodeID, k, committed)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

// SetMultipleKeys sets the values for the multiple keys.
func (state *State) SetMultipleKeys(chaincodeID string, kvs map[string][]byte) error {
	for k, v := range kvs {
		err := state.Set(chaincodeID, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetHash computes new state hash if the stateDelta is to be applied.
// Recomputes only if stateDelta has changed after most recent call to this function
func (state *State) GetHash() ([]byte, error) {
	logger.Debug("Enter - GetHash()")
	if state.updateStateImpl {
		logger.Debug("updating stateImpl with working-set")
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}
	hash, err := state.stateImpl.ComputeCryptoHash()
	if err != nil {
		return nil, err
	}
	logger.Debug("Exit - GetHash()")
	return hash, nil
}

// GetTxStateDeltaHash return the hash of the StateDelta
func (state *State) GetTxStateDeltaHash() map[string][]byte {
	return state.txStateDeltaHash
}

// ClearInMemoryChanges remove from memory all the changes to state
func (state *State) ClearInMemoryChanges(changesPersisted bool) {
	state.stateDelta = statemgmt.NewStateDelta()
	state.txStateDeltaHash = make(map[string][]byte)
	state.stateImpl.ClearWorkingSet(changesPersisted)
}

// getStateDelta get changes in state after most recent call to method clearInMemoryChanges
func (state *State) getStateDelta() *statemgmt.StateDelta {
	return state.stateDelta
}

// GetSnapshot returns a snapshot of the global state for the current block. stateSnapshot.Release()
// must be called once you are done.
func (state *State) GetSnapshot(blockNumber uint64, dbSnapshot *gorocksdb.Snapshot) (*stcomm.StateSnapshot, error) {
	itr, err := stateImpl.GetStateSnapshotIterator(dbSnapshot)
	if err != nil {
		return nil, err
	}
	return stcomm.NewStateSnapshot(blockNumber, itr, dbSnapshot)
}

// FetchStateDeltaFromDB fetches the StateDelta corrsponding to given blockNumber
func (state *State) FetchStateDeltaFromDB(blockNumber uint64) (*statemgmt.StateDelta, error) {
	stateDeltaBytes, err := db.GetDBHandle().GetFromStateDeltaCF(stcomm.EncodeStateDeltaKey(blockNumber))
	if err != nil {
		return nil, err
	}
	if stateDeltaBytes == nil {
		return nil, nil
	}
	stateDelta := statemgmt.NewStateDelta()
	stateDelta.Unmarshal(stateDeltaBytes)
	return stateDelta, nil
}

// CreateDeltaFromGenesis creates a state delta that if applied to the genesis block
// produces the current state. This state delta is created only from the last committed state.
func (state *State) CreateDeltaFromGenesis(blockNumber uint64) (*statemgmt.StateDelta, error) {
	chainSnapshot, err := state.GetSnapshot(blockNumber, db.GetDBHandle().GetSnapshot())
	defer chainSnapshot.Release()
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve DB snapshot to create delta from genesis, (%s)", err)
	}
	logger.Debug("Creating genesis delta")
	delta := statemgmt.NewStateDelta()
	for chainSnapshot.Next() {
		k, v := chainSnapshot.GetRawKeyValue()
		cID, keyID := stcomm.DecodeCompositeKey(k)
		logger.Debugf("Putting key for chaincode ID: %s, key: %s, value: %v", cID, keyID, v)
		delta.Set(cID, keyID, v, nil)
	}
	delta.ApplyChanges(state.stateDelta)
	return delta, nil
}

// FetchBlockStateDeltaFromDB returns a delta from the genesis block to the given block
func (state *State) FetchBlockStateDeltaFromDB(blockNumber uint64) (*statemgmt.StateDelta, error) {
	deltaBytes, err := db.GetDBHandle().GetFromBlockStateCF(stcomm.EncodeStateDeltaKey(blockNumber))
	if err != nil {
		return nil, err
	}

	delta := statemgmt.NewStateDelta()
	err = delta.Unmarshal(deltaBytes)
	if err != nil {
		return nil, err
	}
	return delta, nil
}

// AddChangesForPersistence adds key-value pairs to writeBatch
func (state *State) AddChangesForPersistence(blockNumber uint64, writeBatch *gorocksdb.WriteBatch) {
	logger.Debug("state.addChangesForPersistence()...start")
	if state.updateStateImpl {
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}
	state.stateImpl.AddChangesForPersistence(writeBatch)

	serializedStateDelta := state.stateDelta.Marshal()
	cf := db.GetDBHandle().StateDeltaCF
	logger.Debugf("Adding state-delta corresponding to block number[%d]", blockNumber)
	writeBatch.PutCF(cf, stcomm.EncodeStateDeltaKey(blockNumber), serializedStateDelta)
	if blockNumber >= state.historyStateDeltaSize {
		blockNumberToDelete := blockNumber - state.historyStateDeltaSize
		logger.Debugf("Deleting state-delta corresponding to block number[%d]", blockNumberToDelete)
		writeBatch.DeleteCF(cf, stcomm.EncodeStateDeltaKey(blockNumberToDelete))
	} else {
		logger.Debugf("Not deleting previous state-delta. Block number [%d] is smaller than historyStateDeltaSize [%d]",
			blockNumber, state.historyStateDeltaSize)
	}

	fromGenesisStateDelta, err := state.CreateDeltaFromGenesis(blockNumber)
	if err != nil {
		panic("Unable to create delta from genesis")
	}
	logger.Debugf("Adding state-delta from genesis to block number[%d]", blockNumber)
	writeBatch.PutCF(db.GetDBHandle().BlockStateCF, stcomm.EncodeStateDeltaKey(blockNumber), fromGenesisStateDelta.Marshal())
	logger.Debug("state.addChangesForPersistence()...finished")
}

// ApplyStateDelta applies already prepared stateDelta to the existing state.
// This is an in memory change only. state.CommitStateDelta must be used to
// commit the state to the DB. This method is to be used in state transfer.
func (state *State) ApplyStateDelta(delta *statemgmt.StateDelta) {
	state.stateDelta = delta
	state.updateStateImpl = true
}

// CommitStateDelta commits the changes from state.ApplyStateDelta to the
// DB.
func (state *State) CommitStateDelta() error {
	if state.updateStateImpl {
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}

	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	state.stateImpl.AddChangesForPersistence(writeBatch)
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	return db.GetDBHandle().DB.Write(opt, writeBatch)
}

// DeleteState deletes ALL state keys/values from the DB. This is generally
// only used during state synchronization when creating a new state from
// a snapshot.
func (state *State) DeleteState() error {
	state.ClearInMemoryChanges(false)
	err := db.GetDBHandle().DeleteState()
	if err != nil {
		logger.Errorf("Error deleting state: %s", err)
	}
	return err
}
