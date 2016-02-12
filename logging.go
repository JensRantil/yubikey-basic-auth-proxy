package main

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"time"
)

// Log levels. Only `log` module allowed to be called is fatal (because it's
// more human). Therefor, I'm not including that log level here.
const (
	DEBUG = iota
	INFO
	WARN
	ERROR
)

var (
	logger MethodLogger
)

func init() {
	json := &JSONOutputter{
		os.Stderr,
	}
	recordLogger := &LogRecordLogger{
		json,
	}
	logger = MethodLogger{
		recordLogger,
	}
}

type LogLevel byte

func textualLogLevel(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case ERROR:
		return "ERROR"
	case WARN:
		return "WARN"
	default:
		return "UNKNOWN"
	}
}

type LogRecord struct {
	Level   string
	Time    string
	Type    string
	Payload interface{}
}

type Logger interface {
	Log(level LogLevel, payload interface{})
}

// Helper to add syntactic sugar to logging.
type MethodLogger struct {
	Delegate Logger
}

func (m *MethodLogger) Debug(payload interface{}) {
	m.Delegate.Log(DEBUG, payload)
}

func (m *MethodLogger) Info(payload interface{}) {
	m.Delegate.Log(INFO, payload)
}

func (m *MethodLogger) Warn(payload interface{}) {
	m.Delegate.Log(WARN, payload)
}

func (m *MethodLogger) Error(payload interface{}) {
	m.Delegate.Log(ERROR, payload)
}

type LogWriter interface {
	Write(LogRecord)
}

type LogRecordLogger struct {
	Writer LogWriter
}

func (l *LogRecordLogger) Log(level LogLevel, payload interface{}) {
	l.Writer.Write(LogRecord{
		Level:   textualLogLevel(level),
		Time:    time.Now().Format(time.RFC3339),
		Type:    reflect.TypeOf(payload).Name(),
		Payload: payload,
	})
}

type JSONOutputter struct {
	Writer io.Writer
}

func (j *JSONOutputter) Write(record LogRecord) {
	if data, err := json.Marshal(record); err == nil {
		data = append(data, '\n')
		j.Writer.Write(data)
	} else {
		logger.Warn(UnableToLog{err.Error()})
	}
}
