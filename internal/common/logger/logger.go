// Package logger provides a configured logrus logger instance.
package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	logrus.TextFormatter
}

// Logger wraps a logrus.Logger instance.
type Logger struct {
	*logrus.Logger
}

// New creates a new configured logger instance.
func New() *Logger {
	logger := &Logger{
		Logger: logrus.New(),
	}

	logger.SetFormatter(&CustomFormatter{
		TextFormatter: logrus.TextFormatter{
			TimestampFormat: "15:04:05.000",
			FullTimestamp:   true,
			ForceColors:     true,
		},
	})

	logger.SetOutput(os.Stdout)
	return logger
}

// GetLogger returns a new logger instance.
func GetLogger() *Logger {
	return New()
}
