// +build linux
//
// Wrapper around UNIX syslog, so that it also may be wrapped
// with something else for Windows (Sadly, the stdlib log/syslog
// is frozen, and there is no Window implementation.)
package logger

import (
	sl "log/syslog"
)

type Priority = sl.Priority
type Writer = sl.Writer

const (
	// Severity.

	// From /usr/include/sys/syslog.h.
	// These are the same on Linux, BSD, and OS X.
	LOG_EMERG Priority = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

const (
	// Facility.

	// From /usr/include/sys/syslog.h.
	// These are the same up to LOG_FTP on Linux, BSD, and OS X.
	LOG_KERN Priority = iota << 3
	LOG_USER
	LOG_MAIL
	LOG_DAEMON
	LOG_AUTH
	LOG_SYSLOG
	LOG_LPR
	LOG_NEWS
	LOG_UUCP
	LOG_CRON
	LOG_AUTHPRIV
	LOG_FTP
	_ // unused
	_ // unused
	_ // unused
	_ // unused
	LOG_LOCAL0
	LOG_LOCAL1
	LOG_LOCAL2
	LOG_LOCAL3
	LOG_LOCAL4
	LOG_LOCAL5
	LOG_LOCAL6
	LOG_LOCAL7
)

var (
	l *sl.Writer
)

func New(flags Priority, tag string) (w *Writer, e error) {
	w, e = sl.New(sl.Priority(flags), tag)
	l = w
	return w, e
}

func Alert(s string) error {
		return l.Alert(s)
}
func LogClose() error {
		return l.Close()
}
func LogCrit(s string) error {
		return l.Crit(s)
}
func LogDebug(s string) error {
		return l.Debug(s)
}
func LogEmerg(s string) error {
		return l.Emerg(s)
}
func LogErr(s string) error {
		return l.Err(s)
}
func LogInfo(s string) error {
		return l.Info(s)
}
func LogNotice(s string) error {
		return l.Notice(s)
}
func LogWarning(s string) error {
		return l.Warning(s)
}
func LogWrite(b []byte) (int, error) {
		return l.Write(b)
}
