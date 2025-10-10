// Package logger provides a configured logrus logger instance.
package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	logrus.TextFormatter
}

// Log is the global logger instance.
var Log *logrus.Logger

func init() {
	Log = logrus.New()

	Log.SetFormatter(&CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			TimestampFormat: "15:04:05.000",
			FullTimestamp:   true,
			ForceColors:     true,
		},
	})

	Log.SetOutput(os.Stdout)
}

// GetLogger returns the global logger instance.
func GetLogger() *logrus.Logger {
	return Log
}
