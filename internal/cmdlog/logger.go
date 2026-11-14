// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdlog

import (
	"io"
	"log"
	"os"
)

// Logger provides the small leveled logging surface used by command binaries.
type Logger struct {
	logger *log.Logger
}

// New constructs a logger with the standard command prefix and UTC timestamps.
func New(prefix string) *Logger {
	return &Logger{
		logger: log.New(os.Stderr, prefix+" ", log.LstdFlags|log.LUTC),
	}
}

// SetOutput sets where the logger writes; tests capture it with this.
func (l *Logger) SetOutput(w io.Writer) {
	l.logger.SetOutput(w)
}

func (l *Logger) Infof(format string, args ...any) {
	l.logger.Printf("[INFO] "+format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.logger.Printf("[WARN] "+format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.logger.Printf("[ERROR] "+format, args...)
}
