package crypto

// Ledger exposes the required functions of the core/ledger package to the crypto package
type Ledger interface {
	// GetState get state for chaincodeID and key. If committed is false, this first looks in memory
	// and if missing, pulls from db.  If committed is true, this pulls from the db only.
	GetState(chaincodeID string, key string, committed bool) ([]byte, error)

}
