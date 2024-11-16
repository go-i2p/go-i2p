package logger

import (
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	log  *Logger
	once sync.Once
)

type Logger struct {
	*logrus.Logger
}

type Entry struct {
	Logger
	entry *logrus.Entry
}

func (l *Logger) Warn(args ...interface{}) {
	warnFatal(args)
	l.Logger.Warn(args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	warnFatalf(format, args...)
	l.Logger.Warnf(format, args...)
}

func (l *Logger) Error(args ...interface{}) {
	warnFatal(args)
	l.Logger.Error(args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	warnFatalf(format, args...)
	l.Logger.Errorf(format, args...)
}

func (l *Logger) WithField(key string, value interface{}) *Entry {
	entry := l.Logger.WithField(key, value)
	return &Entry{*l, entry}
}

func (l *Logger) WithFields(fields logrus.Fields) *Entry {
	entry := l.Logger.WithFields(fields)
	return &Entry{*l, entry}
}

func (l *Logger) WithError(err error) *Entry {
	entry := l.Logger.WithError(err)
	return &Entry{*l, entry}
}

func warnFatal(args ...interface{}) {
	if failFast != "" {
		log.Fatal(args)
	}
}

func warnFatalf(format string, args ...interface{}) {
	if failFast != "" {
		log.Fatalf(format, args...)
	}
}

func warnFail() {
	if failFast != "" {
		log.Error("FATAL ERROR")
	}
}

var failFast string

func InitializeGoI2PLogger() {
	once.Do(func() {
		log = &Logger{}
		log.Logger = logrus.New()
		// We do not want to log by default
		log.SetOutput(io.Discard)
		log.SetLevel(logrus.PanicLevel)
		// Check if DEBUG_I2P is set
		if logLevel := os.Getenv("DEBUG_I2P"); logLevel != "" {
			failFast = os.Getenv("WARNFAIL_I2P")
			if failFast != "" {
				logLevel = "debug"
			}
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

// GetGoI2PLogger returns the initialized Logger
func GetGoI2PLogger() *Logger {
	if log == nil {
		InitializeGoI2PLogger()
	}
	return log
}

func init() {
	InitializeGoI2PLogger()
}
