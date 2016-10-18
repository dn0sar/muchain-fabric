package statemgmt

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
)

var mgmtLogger = logging.MustGetLogger("txset_statemgmt")

// StateDelta holds the changes to existing state. This struct is used for holding the uncommitted changes during execution of a tx-batch
// Also, to be used for transferring the state to another peer in chunks
type TxSetStateDelta struct {
	Deltas map[string]*TxSetUpdatedValue
	// RollBackwards allows one to contol whether this delta will roll the state
	// forwards or backwards.
	RollBackwards bool
}

// NewStateDelta constructs an empty StateDelta struct
func NewTxSetStateDelta() *TxSetStateDelta {
	return &TxSetStateDelta{make(map[string]*TxSetUpdatedValue), false}
}

// Get get the state from delta if exists
func (txStateDelta *TxSetStateDelta) Get(txSetID string) *TxSetUpdatedValue {
	// TODO Cache?
	txSetUPValue, ok := txStateDelta.Deltas[txSetID]
	if ok {
		return txSetUPValue
	}
	return nil
}

// Set sets state value for a txSet
func (txStateDelta *TxSetStateDelta) Set(txSetID string, value, prev *pb.TxSetStateValue) {
	txStateDelta.Deltas[txSetID] = &TxSetUpdatedValue{value, prev}
	return
}

// Delete deletes a txSet from the state
func (txStateDelta *TxSetStateDelta) Delete(txSetID string, previousValue *pb.TxSetStateValue) {
	txStateDelta.Deltas[txSetID] = &TxSetUpdatedValue{nil, previousValue}
	return
}

// IsUpdatedValueSet returns true if a update value is already set for
// the given txSetID.
func (txStateDelta *TxSetStateDelta) IsUpdatedValueSet(txSetID string) bool {
	_, ok := txStateDelta.Deltas[txSetID]
	return ok
}

// ApplyChanges merges another delta - if a key is present in both, the value of the existing key is overwritten
func (txStateDelta *TxSetStateDelta) ApplyChanges(anotherTxStateDelta *TxSetStateDelta) {
	for txSetID, txSetUPValue := range anotherTxStateDelta.Deltas {
		existingTxStateDelta, exists := txStateDelta.Deltas[txSetID]
		var previousValue *pb.TxSetStateValue
		if exists {
			// The current state delta already has an updated value for this txSetID.
			previousValue = existingTxStateDelta.GetPreviousValue()
		} else {
			// Use the previous value set in the other state delta
			previousValue = txSetUPValue.GetPreviousValue()
		}
		if txSetUPValue.IsDeleted() {
			txStateDelta.Delete(txSetID, previousValue)
		} else {
			txStateDelta.Set(txSetID, txSetUPValue.GetValue(), previousValue)
		}
	}
}

// IsEmpty checks whether StateDelta contains any data
func (txSetStateDelta *TxSetStateDelta) IsEmpty() bool {
	return len(txSetStateDelta.Deltas) == 0
}

// GetUpdatedTxSetIDs return the txSetIDs that are present in the delta
// If sorted is true, the method return tx Set IDs in lexicographical sorted order
func (txStateDelta *TxSetStateDelta) GetUpdatedTxSetIDs(sorted bool) []string {
	updatedTxSetIds := make([]string, len(txStateDelta.Deltas))
	i := 0
	for k := range txStateDelta.Deltas {
		updatedTxSetIds[i] = k
		i++
	}
	if sorted {
		sort.Strings(updatedTxSetIds)
	}
	return updatedTxSetIds
}

// GetUpdates returns changes associated with given txSetID
func (txStateDelta *TxSetStateDelta) GetUpdates(txSetID string) *TxSetUpdatedValue {
	txSetDelta, exists := txStateDelta.Deltas[txSetID]
	if !exists {
		return nil
	}
	return txSetDelta
}

func (txStateDelta *TxSetStateDelta) getOrCreateTxSetUpValue(txSetID string) *TxSetUpdatedValue {
	txSetValue, ok := txStateDelta.Deltas[txSetID]
	if !ok {
		txSetValue = &TxSetUpdatedValue{nil, nil}
		txStateDelta.Deltas[txSetID] = txSetValue
	}
	return txSetValue
}

// ComputeCryptoHash computes crypto-hash for the data held
// returns nil if no data is present
func (txStateDelta *TxSetStateDelta) ComputeCryptoHash() []byte {
	if txStateDelta.IsEmpty() {
		return nil
	}
	var buffer bytes.Buffer
	sortedTxSetIds := txStateDelta.GetUpdatedTxSetIDs(true)
	for _, txSetID := range sortedTxSetIds {
		buffer.WriteString(txSetID)
		updatedValue := txStateDelta.Deltas[txSetID]
		if !updatedValue.IsDeleted() {
			marshaledValue, err := updatedValue.GetValue().Bytes()
			if err != nil {
				panic(fmt.Errorf("Unable to Marshal the TxSetValue for txSetID: %s, %s", txSetID, err))
			}
			buffer.Write(marshaledValue)
		}
	}
	hashingContent := buffer.Bytes()
	mgmtLogger.Debugf("computing hash on %#v", hashingContent)
	return util.ComputeCryptoHash(hashingContent)
}

// UpdatedValue holds the value for a key
type TxSetUpdatedValue struct {
	Value         *pb.TxSetStateValue
	PreviousValue *pb.TxSetStateValue
}

// IsDeleted checks whether the key was deleted
func (updatedValue *TxSetUpdatedValue) IsDeleted() bool {
	return updatedValue.Value == nil
}

// GetValue returns the value
func (updatedValue *TxSetUpdatedValue) GetValue() *pb.TxSetStateValue {
	return updatedValue.Value
}

// GetPreviousValue returns the previous value
func (updatedValue *TxSetUpdatedValue) GetPreviousValue() *pb.TxSetStateValue {
	return updatedValue.PreviousValue
}

// marshalling / Unmarshalling code
// We need to revisit the following when we define proto messages
// for state related structures for transporting. May be we can
// completely get rid of custom marshalling / Unmarshalling of a state delta

// Marshal serializes the StateDelta
func (txStateDelta *TxSetStateDelta) Marshal() (b []byte) {
	buffer := proto.NewBuffer([]byte{})
	err := buffer.EncodeVarint(uint64(len(txStateDelta.Deltas)))
	if err != nil {
		// in protobuf code the error return is always nil
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
	for txSetID, txSetDelta := range txStateDelta.Deltas {
		buffer.EncodeStringBytes(txSetID)
		txSetDelta.marshal(buffer)
	}
	b = buffer.Bytes()
	return
}

func (txSetDelta *TxSetUpdatedValue) marshal(buffer *proto.Buffer) {
	txSetDelta.marshalValueWithMarker(buffer, txSetDelta.GetValue())
	txSetDelta.marshalValueWithMarker(buffer, txSetDelta.GetPreviousValue())
	return
}

func (txSetDelta *TxSetUpdatedValue) marshalValueWithMarker(buffer *proto.Buffer, value *pb.TxSetStateValue) {
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
	marshaledValue, err := value.Bytes()
	if err != nil {
		panic(fmt.Errorf("Unable to Marshal the TxSetValue %s", err))
	}
	err = buffer.EncodeRawBytes(marshaledValue)
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
}

// Unmarshal deserializes StateDelta
func (txStateDelta *TxSetStateDelta) Unmarshal(bytes []byte) error {
	buffer := proto.NewBuffer(bytes)
	size, err := buffer.DecodeVarint()
	if err != nil {
		return fmt.Errorf("Error unmarashaling size: %s", err)
	}
	txStateDelta.Deltas = make(map[string]*TxSetUpdatedValue, size)
	for i := uint64(0); i < size; i++ {
		txSetID, err := buffer.DecodeStringBytes()
		if err != nil {
			return fmt.Errorf("Error unmarshaling txSetID : %s", err)
		}
		txSetDelta := &TxSetUpdatedValue{}
		err = txSetDelta.unmarshal(buffer)
		if err != nil {
			return fmt.Errorf("Error unmarshalling txSetDelta : %s", err)
		}
		txStateDelta.Deltas[txSetID] = txSetDelta
	}

	return nil
}

func (txSetStateValue *TxSetUpdatedValue) unmarshal(buffer *proto.Buffer) error {
	value, err := txSetStateValue.unmarshalValueWithMarker(buffer)
	if err != nil {
		return fmt.Errorf("Error unmarshaling tx set value (delta): %s", err)
	}
	txSetStateValue.Value = value
	previousValue, err := txSetStateValue.unmarshalValueWithMarker(buffer)
	if err != nil {
		return fmt.Errorf("Error unmarshaling tx set previous value (delta): %s", err)
	}
	txSetStateValue.PreviousValue = previousValue
	return nil
}

func (txSetDelta *TxSetUpdatedValue) unmarshalValueWithMarker(buffer *proto.Buffer) (*pb.TxSetStateValue, error) {
	valueMarker, err := buffer.DecodeVarint()
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling state delta : %s", err)
	}
	if valueMarker == 1 {
		value, err := buffer.DecodeRawBytes(false)
		if err != nil {
			return nil, fmt.Errorf("Error unmarhsaling state delta : %s", err)
		}
		if value != nil {
			return pb.UnmarshalTxSetStateValue(value)
		}
	}
	return nil, nil
}
