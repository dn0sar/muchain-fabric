package raw

import (
	"github.com/hyperledger/fabric/core/ledger/state/txset_state"
	"github.com/hyperledger/fabric/core/db"
	"github.com/tecbot/gorocksdb"
	"github.com/hyperledger/fabric/core/ledger/state"
)

// StateImpl implements raw state management. This implementation does not support computation of crypto-hash of the state.
// It simply stores the compositeKey and value in the db
type TxSetStateImpl struct {
	txSetStateDelta *txset_state.TxSetStateDelta
}

// NewStateImpl constructs new instance of raw state
func NewTxSetStateImpl() *TxSetStateImpl {
	return &TxSetStateImpl{}
}

// Initialize - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) Initialize(configs map[string]interface{}) error {
	return nil
}

// Get - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) Get(txSetID string) ([]byte, error) {
	txSetKey := state_comm.ConstructTxSetKey(txSetID)
	openchainDB := db.GetDBHandle()
	return openchainDB.GetFromTxSetStateCF(txSetKey)
}

// PrepareWorkingSet - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) PrepareWorkingSet(stateDelta *txset_state.TxSetStateDelta) error {
	impl.txSetStateDelta = stateDelta
	return nil
}

// ClearWorkingSet - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) ClearWorkingSet(changesPersisted bool) {
	impl.txSetStateDelta = nil
}

// ComputeCryptoHash - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) ComputeCryptoHash() ([]byte, error) {
	return nil, nil
}

// AddChangesForPersistence - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) AddChangesForPersistence(writeBatch *gorocksdb.WriteBatch) error {
	delta := impl.txSetStateDelta
	if delta == nil {
		return nil
	}
	openchainDB := db.GetDBHandle()
	updatedTxSetIds := delta.GetUpdatedTxSetIDs(false)
	for _, updatedTxSetID := range updatedTxSetIds {
		updatedKV := delta.GetUpdates(updatedTxSetID)
		key := state_comm.ConstructTxSetKey(updatedTxSetID)
		if updatedKV.IsDeleted() {
			writeBatch.DeleteCF(openchainDB.TxSetStateCF, key)
		} else {
			writeBatch.PutCF(openchainDB.TxSetStateCF, key, updatedKV.GetValue())
		}
	}
	return nil
}

// PerfHintKeyChanged - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) PerfHintKeyChanged(txSetID string) {
}

// GetStateSnapshotIterator - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) GetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (state_comm.StateSnapshotIterator, error) {
	panic("Not a full-fledged state implementation. Implemented only for measuring best-case performance benchmark")
}
