package statemgmt

import (
	"github.com/tecbot/gorocksdb"
)

// HashableTxSetState - Interface that is be implemented by state management
// Different state management implementation can be effiecient for computing crypto-hash for
// state under different workload conditions.
type HashableTxSetState interface {

	// Initialize this gives a chance to initialize. For instance, state implementation can load some data from DB
	Initialize(configs map[string]interface{}) error

	// Get get the value from DB
	Get(txSetID string) ([]byte, error)

	// PrepareWorkingSet passes a stateDelta that captures the changes that needs to be applied to the state
	PrepareWorkingSet(txStateDelta *TxStateDelta) error

	// ComputeCryptoHash state implementation to compute crypto-hash of state
	// assuming the stateDelta (passed in PrepareWorkingSet method) is to be applied
	ComputeCryptoHash() ([]byte, error)

	// AddChangesForPersistence state implementation to add all the key-value pair that it needs
	// to persist for committing the  stateDelta (passed in PrepareWorkingSet method) to DB.
	// In addition to the information in the StateDelta, the implementation may also want to
	// persist intermediate results for faster crypto-hash computation
	AddChangesForPersistence(writeBatch *gorocksdb.WriteBatch) error

	// ClearWorkingSet state implementation may clear any data structures that it may have constructed
	// for computing cryptoHash and persisting the changes for the stateDelta (passed in PrepareWorkingSet method)
	ClearWorkingSet(changesPersisted bool)

	// GetStateSnapshotIterator state implementation to provide an iterator that is supposed to give
	// All the key-value of global state. A particular implementation may need to remove additional information
	// that the implementation keeps for faster crypto-hash computation. For instance, filter a few of the
	// key-values or remove some data from particular key-values.
	GetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (StateSnapshotIterator, error)

	// PerfHintKeyChanged state implementation may be provided with some hints before (e.g., during tx execution)
	// the StateDelta is prepared and passed in PrepareWorkingSet method.
	// A state implementation may use this hint for prefetching relevant data so as if this could improve
	// the performance of ComputeCryptoHash method (when gets called at a later time)
	PerfHintKeyChanged(txSetID string)
}