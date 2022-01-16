package socks

import "github.com/hupe1980/golog"

type logger struct {
	logger golog.Logger
}

func (l *logger) logf(level golog.Level, format string, args ...interface{}) {
	l.logger.Printf(level, format, args...)
}

func (l *logger) logDebugf(format string, args ...interface{}) {
	l.logf(golog.DEBUG, format, args...)
}

func (l *logger) logInfof(format string, args ...interface{}) {
	l.logf(golog.INFO, format, args...)
}

func (l *logger) logErrorf(format string, args ...interface{}) {
	l.logf(golog.ERROR, format, args...)
}
