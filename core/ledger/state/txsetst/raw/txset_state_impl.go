package raw

import (
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state"
	"github.com/hyperledger/fabric/core/ledger/state/txsetst/statemgmt"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/tecbot/gorocksdb"
)

// TxSetStateImpl implements raw state management. This implementation does not support computation of crypto-hash of the state.
// It simply stores the compositeKey and value in the db
type TxSetStateImpl struct {
	txSetStateDelta *statemgmt.TxSetStateDelta
}

// NewTxSetStateImpl constructs new instance of raw state
func NewTxSetStateImpl() *TxSetStateImpl {
	return &TxSetStateImpl{}
}

// Initialize - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) Initialize(configs map[string]interface{}) error {
	return nil
}

// Get - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) Get(txSetID string) (*pb.TxSetStateValue, error) {
	txSetKey := stcomm.ConstructTxSetKey(txSetID)
	openchainDB := db.GetDBHandle()
	stateValueBytes, err := openchainDB.GetFromTxSetStateCF(txSetKey)
	if err != nil {
		return nil, err
	}
	if len(stateValueBytes) == 0 {
		return nil, nil
	}
	return pb.UnmarshalTxSetStateValue(stateValueBytes)
}

// PrepareWorkingSet - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) PrepareWorkingSet(stateDelta *statemgmt.TxSetStateDelta) error {
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
		updatedTxSetStateValue := delta.GetUpdates(updatedTxSetID)
		key := stcomm.ConstructTxSetKey(updatedTxSetID)
		// REVIEW: Should I prevent the deletion altogether??
		if updatedTxSetStateValue.IsDeleted() {
			writeBatch.DeleteCF(openchainDB.TxSetStateCF, key)
		} else {
			marshalledTxSetValue, err := updatedTxSetStateValue.GetValue().Bytes()
			if err != nil {
				return err
			}
			writeBatch.PutCF(openchainDB.TxSetStateCF, key, marshalledTxSetValue)
		}
	}
	return nil
}

// PerfHintKeyChanged - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) PerfHintKeyChanged(txSetID string) {
}

// GetTxSetStateSnapshotIterator - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) GetTxSetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (stcomm.StateSnapshotIterator, error) {
	return newTxSetStateSnapshotIterator(snapshot)
	//panic("Not a full-fledged state implementation. Implemented only for measuring best-case performance benchmark")
}
