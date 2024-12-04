// Package querylog provides query log functions and interfaces.
package querylog

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

// Global variables for CAKE configuration
const (
	Megabyte             = 1 << 20
	Kilobyte             = 1 << 10
	timeoutTr            = 30 * time.Second
	hostPortGin          = "11111"
	maxRTTCount          = 1000
	minCakeAcceptableRTT = 10   // in milliseconds
	maxCakeAcceptableRTT = 1000 // in milliseconds
)

var (
	cakeInterfaces = []string{"eth0", "ifb4eth0"}
	totalRTTms     = float64(0.0)
	rttCount       = 0
	cakeLock       = false
	// ------
	watcherRunning = false
	mem            runtime.MemStats
	HeapAlloc      string
	SysMem         string
	Frees          string
	NumGCMem       string
	timeElapsed    string
	latestLog      string

	tlsConf = &tls.Config{
		InsecureSkipVerify: true,
	}
)

func watcher() {

	duration := time.Now()

	// Use Gin as the HTTP router
	gin.SetMode(gin.ReleaseMode)
	recover := gin.New()
	recover.Use(gin.Recovery())
	ginroute := recover

	// Custom NotFound handler
	ginroute.NoRoute(func(c *gin.Context) {
		runtime.GC()
		c.String(http.StatusNotFound, fmt.Sprintln("[404] NOT FOUND"))
	})

	// Print homepage
	ginroute.GET("/", func(c *gin.Context) {
		runtime.GC()
		runtime.ReadMemStats(&mem)
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))

		latestLog = fmt.Sprintf("\n =========================== \n  [ SERVER STATUS ] \n  Last Modified: %v \n  Completed GC Cycles: %v \n  Time Elapsed: %v \n =========================== \n\n", time.Now().UTC().Format(time.RFC850), NumGCMem, timeElapsed)

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))
	})

	ginroute.GET("/netstat", func(c *gin.Context) {
		runtime.GC()
		runtime.ReadMemStats(&mem)
		NumGCMem = fmt.Sprintf("%v", mem.NumGC)
		timeElapsed = fmt.Sprintf("%v", time.Since(duration))

		cmd := exec.Command("tc", "-s", "qdisc")
		stdout, err := cmd.Output()

		if err != nil {
			fmt.Println(err.Error())
			return
		}

		latestLog = fmt.Sprintf("\n =========================== \n  [ SERVER STATUS ] \n  Last Modified: %v \n  Completed GC Cycles: %v \n  Time Elapsed: %v \n =========================== \n  [ CAKE STATUS ] \n  Watcher Running: %v  \n  CAKE Locked: %v \n  RTT Samples: %v \n  Average RTT: %v \n =========================== \n\n %v \n", time.Now().UTC().Format(time.RFC850), NumGCMem, timeElapsed, watcherRunning, cakeLock, rttCount, fmt.Sprintf("%.1fms", (float64(totalRTTms)/float64(rttCount))), string(stdout))

		c.String(http.StatusOK, fmt.Sprintf("%v", latestLog))
	})

	// HTTP proxy server Gin
	httpserverGin := &http.Server{
		Addr:              fmt.Sprintf(":%v", hostPortGin),
		Handler:           ginroute,
		TLSConfig:         tlsConf,
		MaxHeaderBytes:    64 << 10, // 64k
		ReadTimeout:       timeoutTr,
		ReadHeaderTimeout: timeoutTr,
		WriteTimeout:      timeoutTr,
		IdleTimeout:       timeoutTr,
	}
	httpserverGin.SetKeepAlivesEnabled(true)

	notifyGin := fmt.Sprintf("Server is running on %v", fmt.Sprintf(":%v", hostPortGin))

	fmt.Println()
	fmt.Println(notifyGin)
	fmt.Println()
	httpserverGin.ListenAndServe()

}

func validRTTDuration(rtt time.Duration) bool {
	// Validasi apakah RTT cocok untuk Internet traffic atau tidak
	if (rtt/time.Millisecond) < minCakeAcceptableRTT || (rtt/time.Millisecond) > maxCakeAcceptableRTT {
		log.Debug("querylog: skipping CAKE RTT update: invalid RTT %s", rtt)
		return false
	}
	return true
}

func validRTTFloat(rtt float64) bool {
	// Validasi apakah RTT cocok untuk Internet traffic atau tidak
	if rtt < minCakeAcceptableRTT || rtt > maxCakeAcceptableRTT {
		log.Debug("querylog: skipping CAKE RTT update: invalid RTT %v", rtt)
		return false
	}
	return true
}

func updateCakeRTT(rtt time.Duration) {

	cakeLock = true

	if !validRTTDuration(rtt) {
		cakeLock = false
		return
	}

	if rttCount <= maxRTTCount {
		rttCount++
		totalRTTms += (float64(rtt) / float64(time.Millisecond))
	} else if rttCount > maxRTTCount {
		rttCount = 1
		totalRTTms = float64(0.0)
		totalRTTms += (float64(rtt) / float64(time.Millisecond))
	}

	if !validRTTFloat((float64(totalRTTms) / float64(rttCount))) {
		cakeLock = false
		return
	}

	// Gunakan cakeInterfaces langsung di loop
	for _, iface := range cakeInterfaces {
		cmd := exec.Command("tc", "qdisc", "replace", "dev", iface, "root", "cake", "rtt", fmt.Sprintf("%.1fms", (float64(totalRTTms)/float64(rttCount))))
		output, err := cmd.Output()
		if err != nil {
			cakeLock = false
			log.Error("querylog: configuring CAKE on %s: %s: %s", iface, err, string(output))
		} else {
			cakeLock = false
			log.Info("querylog: configured CAKE on %s with RTT %s", iface, fmt.Sprintf("%.1fms", (float64(totalRTTms)/float64(rttCount))))
		}
	}

	cakeLock = false
}

func handleCake(cakeLocked bool, paramsCached bool, paramsElapsed time.Duration) {

	if !cakeLocked {
		// Update CAKE RTT if enabled and cakeInterfaces is not empty
		if !paramsCached && paramsElapsed > 0 {
			updateCakeRTT(paramsElapsed)
		}

		if !watcherRunning {
			watcherRunning = true
			go watcher()
		}
	}

}

// queryLogFileName is a name of the log file.  ".gz" extension is added later
// during compression.
const queryLogFileName = "querylog.json"

// queryLog is a structure that writes and reads the DNS query log.
type queryLog struct {
	// logger is used for logging the operation of the query log.  It must not
	// be nil.
	logger *slog.Logger

	// confMu protects conf.
	confMu *sync.RWMutex

	conf       *Config
	anonymizer *aghnet.IPMut

	findClient func(ids []string) (c *Client, err error)

	// buffer contains recent log entries.  The entries in this buffer must not
	// be modified.
	buffer *container.RingBuffer[*logEntry]

	// logFile is the path to the log file.
	logFile string

	// bufferLock protects buffer.
	bufferLock sync.RWMutex

	// fileFlushLock synchronizes a file-flushing goroutine and main thread.
	fileFlushLock sync.Mutex
	fileWriteLock sync.Mutex

	flushPending bool
}

// ClientProto values are names of the client protocols.
type ClientProto string

// Client protocol names.
const (
	ClientProtoDoH      ClientProto = "doh"
	ClientProtoDoQ      ClientProto = "doq"
	ClientProtoDoT      ClientProto = "dot"
	ClientProtoDNSCrypt ClientProto = "dnscrypt"
	ClientProtoPlain    ClientProto = ""
)

// NewClientProto validates that the client protocol name is valid and returns
// the name as a ClientProto.
func NewClientProto(s string) (cp ClientProto, err error) {
	switch cp = ClientProto(s); cp {
	case
		ClientProtoDoH,
		ClientProtoDoQ,
		ClientProtoDoT,
		ClientProtoDNSCrypt,
		ClientProtoPlain:

		return cp, nil
	default:
		return "", fmt.Errorf("invalid client proto: %q", s)
	}
}

// type check
var _ QueryLog = (*queryLog)(nil)

// Start implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Start(ctx context.Context) (err error) {
	if l.conf.HTTPRegister != nil {
		l.initWeb()
	}

	go l.periodicRotate(ctx)

	return nil
}

// Shutdown implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Shutdown(ctx context.Context) (err error) {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	if l.conf.FileEnabled {
		err = l.flushLogBuffer(ctx)
		if err != nil {
			// Don't wrap the error because it's informative enough as is.
			return err
		}
	}

	return nil
}

func checkInterval(ivl time.Duration) (ok bool) {
	// The constants for possible values of query log's rotation interval.
	const (
		quarterDay  = timeutil.Day / 4
		day         = timeutil.Day
		week        = timeutil.Day * 7
		month       = timeutil.Day * 30
		threeMonths = timeutil.Day * 90
	)

	return ivl == quarterDay || ivl == day || ivl == week || ivl == month || ivl == threeMonths
}

// validateIvl returns an error if ivl is less than an hour or more than a
// year.
func validateIvl(ivl time.Duration) (err error) {
	if ivl < time.Hour {
		return errors.Error("less than an hour")
	}

	if ivl > timeutil.Day*365 {
		return errors.Error("more than a year")
	}

	return nil
}

// WriteDiskConfig implements the [QueryLog] interface for *queryLog.
func (l *queryLog) WriteDiskConfig(c *Config) {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	*c = *l.conf
}

// Clear memory buffer and remove log files
func (l *queryLog) clear(ctx context.Context) {
	l.fileFlushLock.Lock()
	defer l.fileFlushLock.Unlock()

	func() {
		l.bufferLock.Lock()
		defer l.bufferLock.Unlock()

		l.buffer.Clear()
		l.flushPending = false
	}()

	oldLogFile := l.logFile + ".1"
	err := os.Remove(oldLogFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		l.logger.ErrorContext(
			ctx,
			"removing old log file",
			"file", oldLogFile,
			slogutil.KeyError, err,
		)
	}

	err = os.Remove(l.logFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		l.logger.ErrorContext(ctx, "removing log file", "file", l.logFile, slogutil.KeyError, err)
	}

	l.logger.DebugContext(ctx, "cleared")
}

// newLogEntry creates an instance of logEntry from parameters.
func newLogEntry(ctx context.Context, logger *slog.Logger, params *AddParams) (entry *logEntry) {
	q := params.Question.Question[0]
	qHost := aghnet.NormalizeDomain(q.Name)

	entry = &logEntry{
		// TODO(d.kolyshev): Export this timestamp to func params.
		Time:   time.Now(),
		QHost:  qHost,
		QType:  dns.Type(q.Qtype).String(),
		QClass: dns.Class(q.Qclass).String(),

		ClientID:    params.ClientID,
		ClientProto: params.ClientProto,

		Result:   *params.Result,
		Upstream: params.Upstream,

		IP: params.ClientIP,

		Elapsed: params.Elapsed,

		Cached:            params.Cached,
		AuthenticatedData: params.AuthenticatedData,
	}

	if params.ReqECS != nil {
		entry.ReqECS = params.ReqECS.String()
	}

	entry.addResponse(ctx, logger, params.Answer, false)
	entry.addResponse(ctx, logger, params.OrigAnswer, true)

	// function to handle CAKE properly
	handleCake(cakeLock, params.Cached, params.Elapsed)

	return entry
}

// Add implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Add(params *AddParams) {
	var isEnabled, fileIsEnabled bool
	var memSize uint
	func() {
		l.confMu.RLock()
		defer l.confMu.RUnlock()

		isEnabled, fileIsEnabled = l.conf.Enabled, l.conf.FileEnabled
		memSize = l.conf.MemSize
	}()

	if !isEnabled {
		return
	}

	// TODO(s.chzhen):  Pass context.
	ctx := context.TODO()

	err := params.validate()
	if err != nil {
		l.logger.ErrorContext(ctx, "adding record", slogutil.KeyError, err)

		return
	}

	if params.Result == nil {
		params.Result = &filtering.Result{}
	}

	entry := newLogEntry(ctx, l.logger, params)

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.Push(entry)

	if !l.flushPending && fileIsEnabled && l.buffer.Len() >= memSize {
		l.flushPending = true

		// TODO(s.chzhen):  Fix occasional rewrite of entires.
		go func() {
			flushErr := l.flushLogBuffer(ctx)
			if flushErr != nil {
				l.logger.ErrorContext(ctx, "flushing after adding", slogutil.KeyError, flushErr)
			}
		}()
	}
}

// ShouldLog returns true if request for the host should be logged.
func (l *queryLog) ShouldLog(host string, _, _ uint16, ids []string) bool {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	c, err := l.findClient(ids)
	if err != nil {
		// TODO(s.chzhen):  Pass context.
		l.logger.ErrorContext(context.TODO(), "finding client", slogutil.KeyError, err)
	}

	if c != nil && c.IgnoreQueryLog {
		return false
	}

	return !l.isIgnored(host)
}

// isIgnored returns true if the host is in the ignored domains list.  It
// assumes that l.confMu is locked for reading.
func (l *queryLog) isIgnored(host string) bool {
	return l.conf.Ignored.Has(host)
}
