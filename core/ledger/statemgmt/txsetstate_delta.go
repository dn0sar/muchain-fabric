package statemgmt

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/util"
)

// StateDelta holds the changes to existing state. This struct is used for holding the uncommitted changes during execution of a tx-batch
// Also, to be used for transferring the state to another peer in chunks
type TxStateDelta struct {
	TxSetDeltas map[string]*TxSetDelta
	// RollBackwards allows one to contol whether this delta will roll the state
	// forwards or backwards.
	RollBackwards bool
}

// NewStateDelta constructs an empty StateDelta struct
func NewTxSetStateDelta() *TxStateDelta {
	return &TxStateDelta{make(map[string]*TxSetDelta), false}
}

// Get get the state from delta if exists
func (txStateDelta *TxStateDelta) Get(txSetID string) *UpdatedValue {
	// TODO Cache?
	txSetDeltas, ok := txStateDelta.TxSetDeltas[txSetID]
	if ok {
		return txSetDeltas.get()
	}
	return nil
}

// Set sets state value for a key
func (txStateDelta *TxStateDelta) Set(txSetID string, value []byte) {
	txSetDelta := txStateDelta.getOrCreateTxSetDelta(txSetID)
	txSetDelta.set(value)
	return
}

// Delete deletes a key from the state
func (txStateDelta *TxStateDelta) Delete(txSetID string, previousValue []byte) {
	txSetDelta := txStateDelta.getOrCreateTxSetDelta(txSetID)
	txSetDelta.remove(previousValue)
	return
}

// IsUpdatedValueSet returns true if a update value is already set for
// the given chaincode ID and key.
func (txStateDelta *TxStateDelta) IsUpdatedValueSet(txSetID string) bool {
	_, ok := txStateDelta.TxSetDeltas[txSetID]
	return ok
}

// ApplyChanges merges another delta - if a key is present in both, the value of the existing key is overwritten
func (txStateDelta *TxStateDelta) ApplyChanges(anotherTxStateDelta *TxStateDelta) {
	for txSetID, txSetDelta := range anotherTxStateDelta.TxSetDeltas {
		existingTxStateDelta, existingTxSetState := txStateDelta.TxSetDeltas[txSetID]
		var previousValue []byte
		if existingTxSetState {
			// The existing state delta already has an updated value for this txSetID.
			previousValue = existingTxStateDelta.UpdatedKV.PreviousValue
		} else {
			// Use the previous value set in the new state delta
			previousValue = txSetDelta.UpdatedKV.PreviousValue
		}
		if txSetDelta.UpdatedKV.IsDeleted() {
			txStateDelta.Delete(txSetID, previousValue)
		} else {
			txStateDelta.Set(txSetID, txSetDelta.UpdatedKV.Value)
		}
	}
}

// IsEmpty checks whether StateDelta contains any data
func (txSetStateDelta *TxStateDelta) IsEmpty() bool {
	return len(txSetStateDelta.TxSetDeltas) == 0
}

// GetUpdatedTxSetIDs return the txSetIDs that are present in the delta
// If sorted is true, the method return tx Set IDs in lexicographical sorted order
func (txStateDelta *TxStateDelta) GetUpdatedTxSetIDs(sorted bool) []string {
	updatedTxSetIds := make([]string, len(txStateDelta.TxSetDeltas))
	i := 0
	for k := range txStateDelta.TxSetDeltas {
		updatedTxSetIds[i] = k
		i++
	}
	if sorted {
		sort.Strings(updatedTxSetIds)
	}
	return updatedTxSetIds
}

// GetUpdates returns changes associated with given txSetID
func (txStateDelta *TxStateDelta) GetUpdates(txSetID string) *UpdatedValue {
	txSetDelta := txStateDelta.TxSetDeltas[txSetID]
	if txSetDelta == nil {
		return nil
	}
	return txSetDelta.UpdatedKV
}

func (txStateDelta *TxStateDelta) getOrCreateTxSetDelta(txSetID string) *TxSetDelta {
	txSetDelta, ok := txStateDelta.TxSetDeltas[txSetID]
	if !ok {
		txSetDelta = newTxSetDelta(txSetID)
		txStateDelta.TxSetDeltas[txSetID] = txSetDelta
	}
	return txSetDelta
}

// ComputeCryptoHash computes crypto-hash for the data held
// returns nil if no data is present
func (txStateDelta *TxStateDelta) ComputeCryptoHash() []byte {
	if txStateDelta.IsEmpty() {
		return nil
	}
	var buffer bytes.Buffer
	sortedTxSetIds := txStateDelta.GetUpdatedTxSetIDs(true)
	for _, txSetID := range sortedTxSetIds {
		buffer.WriteString(txSetID)
		txSetDelta := txStateDelta.TxSetDeltas[txSetID]
		updatedValue := txSetDelta.get()
		if !updatedValue.IsDeleted() {
			buffer.Write(updatedValue.Value)
		}
	}
	hashingContent := buffer.Bytes()
	logger.Debugf("computing hash on %#v", hashingContent)
	return util.ComputeCryptoHash(hashingContent)
}

//ChaincodeStateDelta maintains state for a chaincode
type TxSetDelta struct {
	TxSetID string
	UpdatedKV  *UpdatedValue
}

func newTxSetDelta(txSetID string) *TxSetDelta {
	return &TxSetDelta{txSetID, nil}
}

func (txSetDelta *TxSetDelta) get() *UpdatedValue {
	return txSetDelta.UpdatedKV
}

func (txSetDelta *TxSetDelta) set(updatedValue []byte) {
	txSetDelta.UpdatedKV.Value = updatedValue
}

func (txSetDelta *TxSetDelta) remove(previousValue []byte) {
	txSetDelta.UpdatedKV.Value = nil
	if txSetDelta.UpdatedKV.PreviousValue == nil {
		txSetDelta.UpdatedKV.PreviousValue = previousValue
	}
}

func (txSetDelta *TxSetDelta) hasChanges() bool {
	return txSetDelta.UpdatedKV != nil
}

// marshalling / Unmarshalling code
// We need to revisit the following when we define proto messages
// for state related structures for transporting. May be we can
// completely get rid of custom marshalling / Unmarshalling of a state delta

// Marshal serializes the StateDelta
func (txStateDelta *TxStateDelta) Marshal() (b []byte) {
	buffer := proto.NewBuffer([]byte{})
	err := buffer.EncodeVarint(uint64(len(txStateDelta.TxSetDeltas)))
	if err != nil {
		// in protobuf code the error return is always nil
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
	for txSetID, txSetDelta := range txStateDelta.TxSetDeltas {
		buffer.EncodeStringBytes(txSetID)
		txSetDelta.marshal(buffer)
	}
	b = buffer.Bytes()
	return
}

func (txSetDelta *TxSetDelta) marshal(buffer *proto.Buffer) {
	txSetDelta.marshalValueWithMarker(buffer, txSetDelta.UpdatedKV.Value)
	txSetDelta.marshalValueWithMarker(buffer, txSetDelta.UpdatedKV.PreviousValue)
	return
}

func (txSetDelta *TxSetDelta) marshalValueWithMarker(buffer *proto.Buffer, value []byte) {
	if value == nil {
		// Just add a marker that the value is nil
		err := buffer.EncodeVarint(uint64(0))
		if err != nil {
			panic(fmt.Errorf("This error should not occur: %s", err))
		}
		return
	}
	err := buffer.EncodeVarint(uint64(1))
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
	// If the value happen to be an empty byte array, it would appear as a nil during
	// deserialization - see method 'unmarshalValueWithMarker'
	err = buffer.EncodeRawBytes(value)
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
}

// Unmarshal deserializes StateDelta
func (txStateDelta *TxStateDelta) Unmarshal(bytes []byte) error {
	buffer := proto.NewBuffer(bytes)
	size, err := buffer.DecodeVarint()
	if err != nil {
		return fmt.Errorf("Error unmarashaling size: %s", err)
	}
	txStateDelta.TxSetDeltas = make(map[string]*TxSetDelta, size)
	for i := uint64(0); i < size; i++ {
		txSetID, err := buffer.DecodeStringBytes()
		if err != nil {
			return fmt.Errorf("Error unmarshaling txSetID : %s", err)
		}
		txSetDelta := newTxSetDelta(txSetID)
		err = txSetDelta.unmarshal(buffer)
		if err != nil {
			return fmt.Errorf("Error unmarshalling txSetDelta : %s", err)
		}
		txStateDelta.TxSetDeltas[txSetID] = txSetDelta
	}

	return nil
}

func (txSetDelta *TxSetDelta) unmarshal(buffer *proto.Buffer) error {
	value, err := txSetDelta.unmarshalValueWithMarker(buffer)
	if err != nil {
		return fmt.Errorf("Error unmarshaling tx set value (delta): %s", err)
	}
	previousValue, err := txSetDelta.unmarshalValueWithMarker(buffer)
	if err != nil {
		return fmt.Errorf("Error unmarshaling tx set previous value (delta): %s", err)
	}
	txSetDelta.UpdatedKV = &UpdatedValue{value, previousValue}
	return nil
}

func (txSetDelta *TxSetDelta) unmarshalValueWithMarker(buffer *proto.Buffer) ([]byte, error) {
	valueMarker, err := buffer.DecodeVarint()
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling state delta : %s", err)
	}
	if valueMarker == 0 {
		return nil, nil
	}
	value, err := buffer.DecodeRawBytes(false)
	if err != nil {
		return nil, fmt.Errorf("Error unmarhsaling state delta : %s", err)
	}
	// protobuff makes an empty []byte into a nil. So, assigning an empty byte array explicitly
	if value == nil {
		value = []byte{}
	}
	return value, nil
}
