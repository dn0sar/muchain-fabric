package helper

import (
	"sync"

	"github.com/spf13/viper"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/op/go-logging"
	"github.com/hyperledger/fabric/core/comm"
)



var (
	secHelper crypto.Peer
	once sync.Once
	helperLogger = logging.MustGetLogger("helper-logger")
)

func GetSecHelper() (crypto.Peer, error) {
	var err error
	once.Do(func() {
		if comm.SecurityEnabled() {
			enrollID := viper.GetString("security.enrollID")
			enrollSecret := viper.GetString("security.enrollSecret")
			if comm.ValidatorEnabled() {
				helperLogger.Debugf("Registering validator with enroll ID: %s", enrollID)
				if err = crypto.RegisterValidator(enrollID, nil, enrollID, enrollSecret); nil != err {
					return
				}
				helperLogger.Debugf("Initializing validator with enroll ID: %s", enrollID)
				secHelper, err = crypto.InitValidator(enrollID, nil)
				if nil != err {
					return
				}
			} else {
				helperLogger.Debugf("Registering non-validator with enroll ID: %s", enrollID)
				if err = crypto.RegisterPeer(enrollID, nil, enrollID, enrollSecret); nil != err {
					return
				}
				helperLogger.Debugf("Initializing non-validator with enroll ID: %s", enrollID)
				secHelper, err = crypto.InitPeer(enrollID, nil)
				if nil != err {
					return
				}
			}
		}
	})
	return secHelper, err
}
