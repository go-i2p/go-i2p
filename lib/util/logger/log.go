package logger

import (
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	log  *logrus.Logger
	once sync.Once
)

func InitializeGoI2PLogger() {
	once.Do(func() {
		log = logrus.New()
		// We do not want to log by default
		log.SetOutput(ioutil.Discard)
		log.SetLevel(logrus.PanicLevel)
		// Check if DEBUG_I2P is set
		if logLevel := os.Getenv("DEBUG_I2P"); logLevel != "" {
			log.SetOutput(os.Stdout)
			switch strings.ToLower(logLevel) {
			case "debug":
				log.SetLevel(logrus.DebugLevel)
			case "warn":
				log.SetLevel(logrus.WarnLevel)
			case "error":
				log.SetLevel(logrus.ErrorLevel)
			default:
				log.SetLevel(logrus.DebugLevel)
			}
			log.WithField("level", log.GetLevel()).Debug("Logging enabled.")
		}
	})
}

// GetGoI2PLogger returns the initialized logger
func GetGoI2PLogger() *logrus.Logger {
	if log == nil {
		InitializeGoI2PLogger()
	}
	return log
}

func init() {
	InitializeGoI2PLogger()
}
