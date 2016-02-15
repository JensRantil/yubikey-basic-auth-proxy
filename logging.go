package main

import (
	"encoding/json"
	"io"
	"reflect"
	"time"
)

type LogLevel struct {
	Level byte
	Name  string
}

// Log levels. Only `log` module allowed to be called is fatal (because it's
// more human). Therefor, I'm not including that log level here.
var logLevels = []LogLevel{
	{0, "DEBUG"},
	{1, "INFO"},
	{2, "WARN"},
	{3, "ERROR"},
	{4, "UNKNOWN"}, // Always log UNKNOWN log levels.
}

// Various views of log levels
var logLevelByName = make(map[string]LogLevel)

func init() {
	for _, logLevel := range logLevels {
		logLevelByName[logLevel.Name] = logLevel
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
	m.Delegate.Log(logLevelByName["DEBUG"], payload)
}

func (m *MethodLogger) Info(payload interface{}) {
	m.Delegate.Log(logLevelByName["INFO"], payload)
}

func (m *MethodLogger) Warn(payload interface{}) {
	m.Delegate.Log(logLevelByName["WARN"], payload)
}

func (m *MethodLogger) Error(payload interface{}) {
	m.Delegate.Log(logLevelByName["ERROR"], payload)
}

type LogWriter interface {
	Write(LogRecord)
}

// Filters logging based log level.
type LogLevelFilter struct {
	Level    LogLevel
	Delegate Logger
}

func (l *LogLevelFilter) Log(level LogLevel, payload interface{}) {
	if level.Level >= l.Level.Level {
		l.Delegate.Log(level, payload)
	}
}

// Wraps payload in a LogRecord and delegates logging to a LogWriter.
type LogRecordLogger struct {
	Writer LogWriter
}

func (l *LogRecordLogger) Log(level LogLevel, payload interface{}) {
	l.Writer.Write(LogRecord{
		Level:   level.Name,
		Time:    time.Now().Format(time.RFC3339),
		Type:    reflect.TypeOf(payload).Name(),
		Payload: payload,
	})
}

// Outputs log records in JSON format.
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
