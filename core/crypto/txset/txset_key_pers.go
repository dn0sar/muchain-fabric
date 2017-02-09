package txset

import (
pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/core/db"
	"github.com/tecbot/gorocksdb"
	"fmt"
	"reflect"
	"github.com/hyperledger/fabric/core/comm"
)

// PersistNonces persists the nonces of the transactions in the local db.
func PersistNonces(txs []*pb.InBlockTransaction) (error) {
	// Only persist if the security is not enabled, otherwise keys should be encrypted with the chainPublicKey
	if !comm.SecurityEnabled() {
		dbHandle := db.GetDBHandle()
		writeBatch := gorocksdb.NewWriteBatch()
		defer writeBatch.Destroy()
		for _, tx := range txs {
			switch tx.Transaction.(type) {
			case *pb.InBlockTransaction_TransactionSet:
				if tx.ConfidentialityLevel == pb.ConfidentialityLevel_CONFIDENTIAL && tx.Nonce != nil {
					nonce, err := dbHandle.GetFromNoncesCF(encodeTxID(tx.Txid));
					if err == nil && nonce != nil && !reflect.DeepEqual(nonce, tx.Nonce) {
						return fmt.Errorf("The transaction with %s id was defined before with a different nonce.", tx.Txid)
					}
					// Note that in case an error occurs the possibly previous nonce is simply deleted
					writeBatch.PutCF(dbHandle.NoncesCF, encodeTxID(tx.Txid), tx.Nonce)
				}
			}
		}
		opt := gorocksdb.NewDefaultWriteOptions()
		defer opt.Destroy()
		dbErr := dbHandle.DB.Write(opt, writeBatch)
		if dbErr != nil {
			return dbErr
		}
		for _, tx := range txs {
			tx.Nonce = nil;
		}
	}
	return nil;
}

func RetrieveNonce(txID string) ([]byte, error) {
	return db.GetDBHandle().GetFromNoncesCF(encodeTxID(txID))
}

func encodeTxID(ID string) ([]byte) {
	return []byte(ID)
}
