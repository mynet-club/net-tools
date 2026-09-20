// Package logx 是极简日志：带级别、写 stdout + 可选轮转文件，不引第三方依赖。
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	}
	return "?"
}

type Logger struct {
	mu       sync.Mutex
	level    Level
	stdout   io.Writer
	file     *os.File
	filePath string
	maxBytes int64
	keep     int
}

func New(level Level, filePath string, maxMb, keep int) *Logger {
	lg := &Logger{
		level:    level,
		stdout:   os.Stdout,
		filePath: filePath,
		maxBytes: int64(maxMb) * 1024 * 1024,
		keep:     keep,
	}
	if filePath != "" && maxMb > 0 {
		_ = os.MkdirAll(filepath.Dir(filePath), 0o700)
		lg.openFile()
	}
	return lg
}

func (l *Logger) openFile() {
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	l.file = f
}

func (l *Logger) rotateIfNeeded() {
	if l.file == nil || l.maxBytes <= 0 {
		return
	}
	st, err := l.file.Stat()
	if err != nil || st.Size() < l.maxBytes {
		return
	}
	_ = l.file.Close()
	l.file = nil
	for i := l.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.filePath, i), fmt.Sprintf("%s.%d", l.filePath, i+1))
	}
	_ = os.Rename(l.filePath, l.filePath+".1")
	l.openFile()
}

func (l *Logger) SetLevel(lv Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = lv
}

func (l *Logger) log(lv Level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lv < l.level {
		return
	}
	line := fmt.Sprintf("%s [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"), lv, fmt.Sprintf(format, args...))
	_, _ = io.WriteString(l.stdout, line)
	if l.file != nil {
		l.rotateIfNeeded()
		if l.file != nil {
			_, _ = l.file.WriteString(line)
		}
	}
}

func (l *Logger) Debugf(format string, args ...any) { l.log(LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.log(LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.log(LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.log(LevelError, format, args...) }

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
