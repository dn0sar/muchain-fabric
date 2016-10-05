package state_comm

// StateSnapshotIterator An interface that is to be implemented by the return value of
// GetStateSnapshotIterator method in the implementation of HashableState interface
type StateSnapshotIterator interface {

	// Next moves to next key-value. Returns true if next key-value exists
	Next() bool

	// GetRawKeyValue returns next key-value
	GetRawKeyValue() ([]byte, []byte)

	// Close releases resources occupied by the iterator
	Close()
}

// RangeScanIterator - is to be implemented by the return value of
// GetRangeScanIterator method in the implementation of HashableState interface
type RangeScanIterator interface {

	// Next moves to next key-value. Returns true if next key-value exists
	Next() bool

	// GetKeyValue returns next key-value
	GetKeyValue() (string, []byte)

	// Close releases resources occupied by the iterator
	Close()
}
