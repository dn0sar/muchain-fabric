package raw

import (
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state"
	"github.com/hyperledger/fabric/core/ledger/state/txsetst/statemgmt"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/tecbot/gorocksdb"
	"github.com/op/go-logging"
	"bytes"
	"github.com/hyperledger/fabric/core/util"
)

var loggerRaw = logging.MustGetLogger("txsetst_raw")

// TxSetStateImpl implements raw state management. This implementation does not support computation of crypto-hash of the state.
// It simply stores the compositeKey and value in the db
type TxSetStateImpl struct {
	txSetStateDelta *statemgmt.TxSetStateDelta
	prevHash []byte
	recomputeHash bool
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
	hyperDB := db.GetDBHandle()
	stateValueBytes, err := hyperDB.GetFromTxSetStateCF(txSetKey)
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
	if !impl.recomputeHash {
		return impl.prevHash, nil
	}
	hyperDB := db.GetDBHandle()
	var resBuffer bytes.Buffer
	stateIterator := hyperDB.GetTxSetStateCFIterator()
	defer stateIterator.Close()
	for stateIterator.SeekToFirst(); stateIterator.Valid(); stateIterator.Next() {
		k := stcomm.Copy(stateIterator.Key().Data())
		resBuffer.Write(k)
		v := stcomm.Copy(stateIterator.Value().Data())
		resBuffer.Write(v)
	}
	impl.prevHash = util.ComputeCryptoHash(resBuffer.Bytes())
	impl.recomputeHash = false
	return impl.prevHash, nil
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
			impl.recomputeHash = true
		}
	}
	return nil
}

// PerfHintKeyChanged - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) PerfHintKeyChanged(txSetID string) {
}

// GetTxSetStateSnapshotIterator - method implementation for interface 'statemgmt.HashableTxSetState'
func (impl *TxSetStateImpl) GetTxSetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (stcomm.StateSnapshotIterator, error) {
	loggerRaw.Warningf("Not a full-fledged state implementation. Implemented only for measuring best-case performance benchmark")
	return newTxSetStateSnapshotIterator(snapshot)
}
