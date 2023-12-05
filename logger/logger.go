package logger

import "context"

type BaseLogger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warning(format string, args ...interface{})
	Error(format string, args ...interface{})
}

type ContextInterface interface {
	BaseLogger
	Ctx() context.Context
	UpdateContextToLoggerContext(context.Context) ContextInterface
}

type Logger interface {
	BaseLogger
	// CDebugf logs a message at debug level, with a context and
	// formatting args.
	CDebugf(ctx context.Context, format string, args ...interface{})
	// CInfo logs a message at info level, with a context and formatting args.
	CInfof(ctx context.Context, format string, args ...interface{})
	// Notice logs a message at notice level, with formatting args.
	Notice(format string, args ...interface{})
	// CNoticef logs a message at notice level, with a context and
	// formatting args.
	CNoticef(ctx context.Context, format string, args ...interface{})
	// Warning logs a message at warning level, with formatting args.
	CWarningf(ctx context.Context, format string, args ...interface{})
	// Error logs a message at error level, with formatting args
	Errorf(format string, args ...interface{})
	// CErrorf logs a message at error level, with a context and
	// formatting args.
	CErrorf(ctx context.Context, format string, args ...interface{})
	// Critical logs a message at critical level, with formatting args.
	Critical(format string, args ...interface{})
	// CCriticalf logs a message at critical level, with a context and
	// formatting args.
	CCriticalf(ctx context.Context, format string, args ...interface{})
	// Fatalf logs a message at fatal level, with formatting args.
	Fatalf(format string, args ...interface{})
	// Fatalf logs a message at fatal level, with a context and formatting args.
	CFatalf(ctx context.Context, format string, args ...interface{})
	// Profile logs a profile message, with formatting args.
	Profile(fmts string, arg ...interface{})

	// Returns a logger that is like the current one, except with
	// more logging depth added on.
	CloneWithAddedDepth(depth int) Logger
	// Configure sets the style, debug level, and filename of the
	// logger.  Output isn't redirected to the file until
	// the log file rotation is configured.
	Configure(style string, debug bool, filename string)
}

type Context struct {
	ctx context.Context
	Logger
}

func NewContext(c context.Context, l Logger) Context {
	return Context{ctx: c, Logger: l}
}

var _ ContextInterface = Context{}

func (c Context) Ctx() context.Context {
	return c.ctx
}

func (c Context) UpdateContextToLoggerContext(ctx context.Context) ContextInterface {
	return NewContext(ctx, c.Logger)
}

func (c Context) Debug(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CDebugf(c.ctx, format, arg...)
}

func (c Context) Info(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CInfof(c.ctx, format, arg...)
}

func (c Context) Notice(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CNoticef(c.ctx, format, arg...)
}

func (c Context) Warning(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CWarningf(c.ctx, format, arg...)
}

func (c Context) Error(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CErrorf(c.ctx, format, arg...)
}

func (c Context) Critical(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CCriticalf(c.ctx, format, arg...)
}

func (c Context) Fatal(format string, arg ...interface{}) {
	c.Logger.CloneWithAddedDepth(1).CFatalf(c.ctx, format, arg...)
}

func prepareString(
	ctx context.Context, fmts string) string {
	return fmts
}

type Null struct{}

func NewNull() *Null {
	return &Null{}
}

// Verify Null fully implements the Logger interface.
var _ Logger = (*Null)(nil)

func (l *Null) Debug(format string, args ...interface{})                       {}
func (l *Null) Info(format string, args ...interface{})                        {}
func (l *Null) Warning(format string, args ...interface{})                     {}
func (l *Null) Notice(format string, args ...interface{})                      {}
func (l *Null) Errorf(format string, args ...interface{})                      {}
func (l *Null) Critical(format string, args ...interface{})                    {}
func (l *Null) CCriticalf(ctx context.Context, fmt string, arg ...interface{}) {}
func (l *Null) Fatalf(fmt string, arg ...interface{})                          {}
func (l *Null) CFatalf(ctx context.Context, fmt string, arg ...interface{})    {}
func (l *Null) Profile(fmts string, arg ...interface{})                        {}
func (l *Null) CDebugf(ctx context.Context, fmt string, arg ...interface{})    {}
func (l *Null) CInfof(ctx context.Context, fmt string, arg ...interface{})     {}
func (l *Null) CNoticef(ctx context.Context, fmt string, arg ...interface{})   {}
func (l *Null) CWarningf(ctx context.Context, fmt string, arg ...interface{})  {}
func (l *Null) CErrorf(ctx context.Context, fmt string, arg ...interface{})    {}
func (l *Null) Error(fmt string, arg ...interface{})                           {}
func (l *Null) Configure(style string, debug bool, filename string)            {}

func (l *Null) CloneWithAddedDepth(depth int) Logger { return l }

func (l *Null) Shutdown() {}
