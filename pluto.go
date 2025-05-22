package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	certFile = flag.String("cert", "", "Path to TLS certificate file")
	keyFile  = flag.String("key", "", "Path to TLS private key file")
)

var emailRegExp = regexp.MustCompile(`^<((\S+)@(\S+\.\S+))>$`)

const TorSocksProxyAddr = "127.0.0.1:9050"
const RelayWorkerCount = 5 
const DeliveryTimeout = 30 * time.Second 

var mailQueue chan *Envelope

type Server struct {
	Name      string
	Addr      string
	Handler   Handler
	TLSConfig *tls.Config
	Debug     bool
	ErrorLog  *log.Logger
}

type conn struct {
	remoteAddr    string
	server        *Server
	rwc           net.Conn
	text          *textproto.Conn
	tlsState      *tls.ConnectionState
	fromAgent     string
	mailFrom      string
	mailTo        []string
	mailData      *bytes.Buffer
	helloRecieved bool
	quitSent      bool
	mu            sync.Mutex
}

type HandlerFunc func(envelope *Envelope) error

func (f HandlerFunc) ServeSMTP(envelope *Envelope) error {
	return f(envelope)
}

type Envelope struct {
	FromAgent   string
	RemoteAddr  string
	MessageFrom string
	MessageTo   string
	MessageData io.Reader
	ReceivedAt  time.Time
	RetryCount  int
}

type Handler interface {
	ServeSMTP(envelope *Envelope) error
}

type ServeMux struct {
	mu sync.RWMutex
	m  map[string]map[string]muxEntry
}

type muxEntry struct {
	h       Handler
	pattern string
}

type torListener struct {
	net.Listener
}

func (l *torListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (srv *Server) logfd(format string, args ...interface{}) {
	if srv.Debug {
		srv.logf(format, args...)
	}
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) newConn(rwc net.Conn) (c *conn, err error) {
	c = new(conn)
	c.resetSession()
	c.remoteAddr = rwc.RemoteAddr().String()
	c.server = srv
	c.rwc = rwc
	c.text = textproto.NewConn(c.rwc)
	c.tlsState = nil
	return c, nil
}

func (srv *Server) ListenAndServe() error {
	if srv.Name == "" {
		srv.Name = "localhost"
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":smtp"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) ListenAndServeTLS() error {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = config
	return srv.ListenAndServe()
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	var tempDelay time.Duration
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("smtp: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		c, err := srv.newConn(rw)
		if err != nil {
			continue
		}
		go c.serve()
	}
}

func (srv *Server) ServeTLS(l net.Listener) error {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = config
	return srv.Serve(l)
}

func (c *conn) serve() {
	c.server.logfd("INFO: Handling new connection from " + c.remoteAddr)
	c.server.logfd("<%d %s %s\n", 220, c.server.Name, "ESMTP")
	err := c.text.PrintfLine("%d %s %s", 220, c.server.Name, "ESMTP")
	if err != nil {
		c.server.logf("%v\n", err)
		return
	}
	for !c.quitSent && err == nil {
		err = c.readCommand()
		if err != nil {
			c.server.logf("%v\n", err)
		}
	}
	c.text.Close()
	c.rwc.Close()
}

func (c *conn) resetSession() {
	c.mailFrom = ""
	c.mailTo = make([]string, 0)
	c.mailData = nil
}

func isOnionDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	return strings.HasSuffix(domain, ".onion")
}

func SplitAddress(address string) (string, string, error) {
	if !strings.Contains(address, "@") {
		return "", "", errors.New("invalid email address format: missing '@'")
	}

	sepInd := strings.LastIndex(address, "@")
	if sepInd == -1 {
		return "", "", errors.New("invalid email address format")
	}

	localPart := address[:sepInd]
	domainPart := address[sepInd+1:]

	if !isOnionDomain(domainPart) {
		return "", "", errors.New("Only .onion domains are allowed")
	}

	return localPart, domainPart, nil
}

func (c *conn) readCommand() error {
	s, err := c.text.ReadLine()
	if err != nil {
		return err
	}
	c.server.logfd(">%s\n", s)
	parts := strings.Split(s, " ")
	if len(parts) <= 0 {
		c.server.logfd("<%d %s\n", 500, "Command not recognized")
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
	parts[0] = strings.ToUpper(parts[0])

	switch parts[0] {
	case "HELO":
		if len(parts) < 2 {
			c.server.logfd("<%d %s\n", 501, "Not enough arguments")
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		c.fromAgent = parts[1]
		c.resetSession()
		c.helloRecieved = true
		c.server.logfd("<%d %s %s\n", 250, "Hello", parts[1])
		return c.text.PrintfLine("%d %s %s", 250, "Hello", parts[1])
	case "EHLO":
		if len(parts) < 2 {
			c.server.logfd("<%d %s\n", 501, "Not enough arguments")
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		c.fromAgent = parts[1]
		c.resetSession()
		c.helloRecieved = true
		c.server.logfd("<%d-%s %s\n", 250, "Greets", parts[1])
		err := c.text.PrintfLine("%d-%s %s", 250, "Greets", parts[1])
		if err != nil {
			return err
		}
		if c.server.TLSConfig != nil && c.tlsState == nil {
			c.server.logfd("<%d-%s\n", 250, "STARTTLS")
			err = c.text.PrintfLine("%d-%s", 250, "STARTTLS")
			if err != nil {
				return err
			}
		}
		c.server.logfd("<%d-%s\n", 250, "PIPELINING")
		err = c.text.PrintfLine("%d-%s", 250, "PIPELINING")
		if err != nil {
			return err
		}
		c.server.logfd("<%d-%s\n", 250, "SMTPUTF8")
		err = c.text.PrintfLine("%d-%s", 250, "SMTPUTF8")
		if err != nil {
			return err
		}
		c.server.logfd("<%d %s\n", 250, "8BITMIME")
		return c.text.PrintfLine("%d %s", 250, "8BITMIME")
	case "STARTTLS":
		if c.server.TLSConfig == nil {
			c.server.logfd("<%d %s\n", 454, "TLS unavailable on the server")
			return c.text.PrintfLine("%d %s", 454, "TLS unavailable on the server")
		}
		if c.tlsState != nil {
			c.server.logfd("<%d %s\n", 454, "TLS session already active")
			return c.text.PrintfLine("%d %s", 454, "TLS session already active")
		}
		c.server.logfd("<%d %s\n", 220, "Ready to start TLS")
		err = c.text.PrintfLine("%d %s", 220, "Ready to start TLS")
		if err != nil {
			return err
		}
		tlsconn := tls.Server(c.rwc, c.server.TLSConfig)
		err = tlsconn.Handshake()
		if err != nil {
			return err
		}
		c.rwc = tlsconn
		c.text = textproto.NewConn(c.rwc)
		c.tlsState = new(tls.ConnectionState)
		*c.tlsState = tlsconn.ConnectionState()
		c.resetSession()
		c.helloRecieved = false
	case "MAIL":
		if c.mailFrom != "" {
			c.server.logfd("<%d %s\n", 503, "MAIL command already recieved")
			return c.text.PrintfLine("%d %s", 503, "MAIL command already recieved")
		}
		if len(parts) < 2 {
			c.server.logfd("<%d %s\n", 501, "Not enough arguments")
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "FROM:") {
			c.server.logfd("<%d %s\n", 501, "MAIL command must be immediately succeeded by 'FROM:'")
			return c.text.PrintfLine("%d %s", 501, "MAIL command must be immediately succeeded by 'FROM:'")
		}
		i := strings.Index(parts[1], ":")
		if i < 0 || !emailRegExp.MatchString(parts[1][i+1:]) {
			c.server.logfd("<%d %s\n", 501, "MAIL command contained invalid address")
			return c.text.PrintfLine("%d %s", 501, "MAIL command contained invalid address")
		}
		from := emailRegExp.FindStringSubmatch(parts[1][i+1:])[1]
		_, _, err := SplitAddress(from)
		if err != nil {
			c.server.logfd("<%d %s\n", 501, err.Error())
			return c.text.PrintfLine("%d %s", 501, err.Error())
		}
		c.mailFrom = from
		c.server.logfd("<%d %s\n", 250, "Ok")
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "RCPT":
		if c.mailFrom == "" {
			c.server.logfd("<%d %s\n", 503, "Bad sequence of commands")
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		if len(parts) < 2 {
			c.server.logfd("<%d %s\n", 501, "Not enough arguments")
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "TO:") {
			c.server.logfd("<%d %s\n", 501, "RCPT command must be immediately succeeded by 'TO:'")
			return c.text.PrintfLine("%d %s", 501, "RCPT command must be immediately succeeded by 'TO:'")
		}
		i := strings.Index(parts[1], ":")
		if i < 0 || !emailRegExp.MatchString(parts[1][i+1:]) {
			c.server.logfd("<%d %s\n", 501, "RCPT command contained invalid address")
			return c.text.PrintfLine("%d %s", 501, "RCPT command contained invalid address")
		}
		to := emailRegExp.FindStringSubmatch(parts[1][i+1:])[1]
		_, _, err := SplitAddress(to)
		if err != nil {
			c.server.logfd("<%d %s\n", 501, err.Error())
			return c.text.PrintfLine("%d %s", 501, err.Error())
		}
		c.mailTo = append(c.mailTo, to)
		c.server.logfd("<%d %s\n", 250, "Ok")
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "DATA":
		if c.mailTo == nil || c.mailFrom == "" || len(c.mailTo) == 0 {
			c.server.logfd("<%d %s\n", 503, "Bad sequence of commands")
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		err := c.text.PrintfLine("%d %s", 354, "End data with <CR><LF>.<CR><LF>")
		if err != nil {
			return err
		}
		b, err := c.text.ReadDotBytes()
		if err != nil {
			return err
		}
		c.mailData = bytes.NewBuffer(b)

		for _, recipient := range c.mailTo {
			queuedEnvelope := &Envelope{
				FromAgent:   c.fromAgent,
				RemoteAddr:  c.remoteAddr,
				MessageFrom: c.mailFrom,
				MessageTo:   recipient,
				MessageData: bytes.NewReader(c.mailData.Bytes()), 
				ReceivedAt:  time.Now(),
				RetryCount:  0,
			}
			select {
			case mailQueue <- queuedEnvelope:
				log.Printf("INFO: Mail from %s to %s queued for delivery.", queuedEnvelope.MessageFrom, queuedEnvelope.MessageTo)
			default:
				log.Printf("WARNING: Mail queue is full, dropping message from %s to %s.", queuedEnvelope.MessageFrom, queuedEnvelope.MessageTo)
			}
		}

		c.resetSession()
		c.server.logfd("<%d %s\n", 250, "OK")
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "RSET":
		c.resetSession()
		c.server.logfd("<%d %s\n", 250, "Ok")
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "VRFY":
		c.server.logfd("<%d %s\n", 250, "OK")
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "EXPN":
		c.server.logfd("<%d %s\n", 250, "OK")
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "HELP":
		c.server.logfd("<%d %s\n", 250, "OK")
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "NOOP":
		c.server.logfd("<%d %s\n", 250, "OK")
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "QUIT":
		c.server.logfd("<%d %s\n", 221, "OK")
		c.quitSent = true
		return c.text.PrintfLine("%d %s", 221, "OK")
	default:
		c.server.logfd("<%d %s\n", 500, "Command not recognized")
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
	return nil
}

func NewServeMux() *ServeMux { return &ServeMux{m: make(map[string]map[string]muxEntry)} }

var DefaultServeMux = NewServeMux()

func CanonicalizeEmail(local string) string {
	local = strings.TrimSpace(local)
	local = strings.ToLower(local)
	local = strings.Replace(local, ".", "", -1)
	if li := strings.LastIndex(local, "+"); li > 0 {
		local = local[:li]
	}
	return local
}

func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	var localPart, domainPart string

	if strings.Contains(pattern, "@") {
		parts := strings.Split(pattern, "@")
		if len(parts) == 2 {
			localPart = parts[0]
			domainPart = parts[1]
		} else {
			log.Fatalf("invalid pattern format for ServeMux.Handle: %s", pattern)
		}
	} else {
		log.Fatalf("invalid pattern format, missing '@' in ServeMux.Handle pattern: %s", pattern)
	}

	if localPart == "" {
		localPart = "*"
	}

	canonicalLocalPart := CanonicalizeEmail(localPart)

	dp, ok := mux.m[domainPart]
	if !ok {
		dp = make(map[string]muxEntry)
		mux.m[domainPart] = dp
	}
	dp[canonicalLocalPart] = muxEntry{h: handler, pattern: pattern}
}

func (mux *ServeMux) HandleFunc(pattern string, handler func(envelope *Envelope) error) {
	mux.Handle(pattern, HandlerFunc(handler))
}

func (mux *ServeMux) ServeSMTP(envelope *Envelope) error {
	l, d, err := SplitAddress(envelope.MessageTo)
	if err != nil {
		return fmt.Errorf("Invalid Address: %w", err)
	}
	cl := CanonicalizeEmail(l)

	mux.mu.RLock()
	defer mux.mu.RUnlock()

	if dp, ok := mux.m[d]; ok {
		if ap, ok := dp[cl]; ok {
			return ap.h.ServeSMTP(envelope)
		}
		if ap, ok := dp["*"]; ok {
			return ap.h.ServeSMTP(envelope)
		}
	}

	if isOnionDomain(d) {
		if dp, ok := mux.m["*.onion"]; ok {
			if ap, ok := dp[cl]; ok {
				return ap.h.ServeSMTP(envelope)
			}
			if ap, ok := dp["*"]; ok {
				return ap.h.ServeSMTP(envelope)
			}
		}
	}

	if dp, ok := mux.m["*"]; ok {
		if ap, ok := dp[cl]; ok {
			return ap.h.ServeSMTP(envelope)
		}
		if ap, ok := dp["*"]; ok {
			return ap.h.ServeSMTP(envelope)
		}
	}

	return errors.New("Bad Address: No handler found for " + envelope.MessageTo)
}

func createTorListener(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host != "127.0.0.1" && host != "localhost" {
		return nil, errors.New("server must listen on localhost for Tor hidden service via torrc configuration")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &torListener{
		Listener: listener,
	}, nil
}

func smtpRelay(envelope *Envelope) error {
	_, recipientDomain, err := SplitAddress(envelope.MessageTo)
	if err != nil {
		return fmt.Errorf("invalid recipient address for relay: %w", err)
	}

	targetAddr := net.JoinHostPort(recipientDomain, "2525")

	netDialer := &net.Dialer{
		Timeout: DeliveryTimeout,
	}

	torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, netDialer)
	if err != nil {
		return fmt.Errorf("failed to create Tor SOCKS5 dialer for relay: %w", err)
	}

	_ , cancel := context.WithTimeout(context.Background(), DeliveryTimeout)
	defer cancel()

	conn, err := torDialer.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s via Tor (timeout %v): %w", targetAddr, DeliveryTimeout, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(DeliveryTimeout))

	c, err := smtp.NewClient(conn, recipientDomain)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client for %s: %w", targetAddr, err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         recipientDomain,
		}
		if err = c.StartTLS(config); err != nil {
			log.Printf("WARNING: Failed to STARTTLS with %s: %v", targetAddr, err)
		}
	}

	if err = c.Mail(envelope.MessageFrom); err != nil {
		return fmt.Errorf("failed to set MAIL FROM %s: %w", envelope.MessageFrom, err)
	}

	if err = c.Rcpt(envelope.MessageTo); err != nil {
		return fmt.Errorf("failed to set RCPT TO %s: %w", envelope.MessageTo, err)
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("failed to get DATA writer: %w", err)
	}
	defer wc.Close()

	if _, err = io.Copy(wc, envelope.MessageData); err != nil {
		return fmt.Errorf("failed to write email data: %w", err)
	}

	log.Printf("Successfully relayed mail from %s to %s via Tor", envelope.MessageFrom, envelope.MessageTo)
	return nil
}

func StartRelayWorkers(queue chan *Envelope, workerCount int) {
	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			log.Printf("Relay Worker %d started.", workerID)
			for envelope := range queue {
				log.Printf("Relay Worker %d: Attempting delivery for mail from %s to %s (Retry %d)", 
					workerID, envelope.MessageFrom, envelope.MessageTo, envelope.RetryCount)
				err := smtpRelay(envelope)
				if err != nil {
					log.Printf("Relay Worker %d: Delivery failed for mail from %s to %s: %v", 
						workerID, envelope.MessageFrom, envelope.MessageTo, err)
					
					if envelope.RetryCount < 3 {
						envelope.RetryCount++
						go func(env *Envelope) {
							time.Sleep(5 * time.Second * time.Duration(env.RetryCount)) 
							select {
								case queue <- env:
									log.Printf("Relay Worker %d: Re-queued mail from %s to %s for retry %d.", workerID, env.MessageFrom, env.MessageTo, env.RetryCount)
								default:
									log.Printf("Relay Worker %d: Failed to re-queue mail from %s to %s, queue full. Dropped after %d retries.", workerID, env.MessageFrom, env.MessageTo, env.RetryCount-1)
							}
						}(envelope)
					} else {
						log.Printf("Relay Worker %d: Mail from %s to %s permanently failed after %d retries.", workerID, envelope.MessageFrom, envelope.MessageTo, envelope.RetryCount)
					}
				} else {
					log.Printf("Relay Worker %d: Successfully delivered mail from %s to %s.", workerID, envelope.MessageFrom, envelope.MessageTo)
				}
			}
			log.Printf("Relay Worker %d stopped.", workerID) 
		}(i)
	}
}

func main() {
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("Both -cert and -key flags are required")
	}

	mailQueue = make(chan *Envelope, 100)

	StartRelayWorkers(mailQueue, RelayWorkerCount)

	server := &Server{
		Name:    "localhost",
		Addr:    "127.0.0.1:2525",
		Handler: DefaultServeMux,
		Debug:   true,
	}

	DefaultServeMux.HandleFunc("*@*.onion", func(envelope *Envelope) error {
		return nil
	})

	listener, err := createTorListener(server.Addr)
	if err != nil {
		log.Fatalf("Failed to create Tor listener: %v", err)
	}

	log.Printf("Starting SMTP server as Tor hidden service on %s", server.Addr)
	log.Printf("Expecting Tor SOCKS5 proxy to be running on %s", TorSocksProxyAddr)
	log.Printf("Starting %d relay workers with a %v delivery timeout.", RelayWorkerCount, DeliveryTimeout)
	if err := server.ServeTLS(listener); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	select {} 
}