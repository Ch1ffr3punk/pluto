package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"
)

var (
	certFile         = flag.String("cert", "", "Path to TLS certificate file")
	keyFile          = flag.String("key", "", "Path to TLS private key file")
	minicryptKeyFile = flag.String("mk", "", "Path to Minicrypt private key file")
)

var emailRegExp = regexp.MustCompile(`^<((\S+)@(\S+\.\S+))>$`)
var mailQueue chan *Envelope
var mailQueueMutex sync.Mutex

const (
	TorSocksProxyAddr   = "127.0.0.1:9050"
	RelayWorkerCount    = 5
	DeliveryTimeout     = 30 * time.Second
	RewriteFromAddress  = "orb@pluto.onion"
)

type Server struct {
	Name         string
	Addr         string
	Handler      Handler
	TLSConfig    *tls.Config
	Debug        bool
	ErrorLog     *log.Logger
	MinicryptKey *memguard.LockedBuffer
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

type Envelope struct {
	FromAgent           string
	RemoteAddr          string
	OriginalMessageFrom string
	MessageFrom         string
	MessageTo           string
	MessageData         io.Reader
	ReceivedAt          time.Time
	RetryCount          int
}

type HandlerFunc func(envelope *Envelope) error

func (f HandlerFunc) ServeSMTP(envelope *Envelope) error {
	return f(envelope)
}

type Handler interface {
	ServeSMTP(envelope *Envelope) error
}

type ServeMux struct {
	mu     sync.RWMutex
	m      map[string]map[string]muxEntry
	server *Server
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

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) logfd(format string, args ...interface{}) {
	if srv.Debug {
	}
}

func (srv *Server) newConn(rwc net.Conn) (c *conn, err error) {
	c = &conn{
		remoteAddr: rwc.RemoteAddr().String(),
		server:     srv,
		rwc:        rwc,
		text:       textproto.NewConn(rwc),
		mailTo:     make([]string, 0),
	}
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
	c.server.logf("INFO: Connection established from %s", c.remoteAddr)
	err := c.text.PrintfLine("%d %s %s", 220, c.server.Name, "ESMTP")
	if err != nil {
		c.server.logf("ERROR: Connection error with %s: %v", c.remoteAddr, err)
		return
	}
	for !c.quitSent && err == nil {
		err = c.readCommand()
	}
	c.text.Close()
	c.rwc.Close()
	c.server.logf("INFO: Connection closed from %s", c.remoteAddr)
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
		return "", "", errors.New("only .onion domains are allowed")
	}
	return localPart, domainPart, nil
}

func (c *conn) readCommand() error {
	s, err := c.text.ReadLine()
	if err != nil {
		return err
	}
	parts := strings.Split(s, " ")
	if len(parts) <= 0 {
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
	parts[0] = strings.ToUpper(parts[0])
	switch parts[0] {
	case "HELO", "EHLO":
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		c.fromAgent = parts[1]
		c.resetSession()
		c.helloRecieved = true
		responses := []string{
			fmt.Sprintf("%d-%s %s", 250, "Greets", parts[1]),
			fmt.Sprintf("%d-%s", 250, "PIPELINING"),
			fmt.Sprintf("%d-%s", 250, "SMTPUTF8"),
		}
		if c.server.TLSConfig != nil && c.tlsState == nil {
			responses = append([]string{fmt.Sprintf("%d-%s", 250, "STARTTLS")}, responses...)
		}
		for i, resp := range responses {
			if i == len(responses)-1 {
				resp = strings.Replace(resp, "-", " ", 1)
			}
			if err := c.text.PrintfLine(resp); err != nil {
				return err
			}
		}
		return nil
	case "STARTTLS":
		if c.server.TLSConfig == nil {
			return c.text.PrintfLine("%d %s", 454, "TLS unavailable on the server")
		}
		if c.tlsState != nil {
			return c.text.PrintfLine("%d %s", 454, "TLS session already active")
		}
		if err := c.text.PrintfLine("%d %s", 220, "Ready to start TLS"); err != nil {
			return err
		}
		tlsconn := tls.Server(c.rwc, c.server.TLSConfig)
		if err := tlsconn.Handshake(); err != nil {
			return err
		}
		c.rwc = tlsconn
		c.text = textproto.NewConn(c.rwc)
		state := tlsconn.ConnectionState()
		c.tlsState = &state
		c.resetSession()
		c.helloRecieved = false
		return nil
	case "MAIL":
		if c.mailFrom != "" {
			return c.text.PrintfLine("%d %s", 503, "MAIL command already received")
		}
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "FROM:") {
			return c.text.PrintfLine("%d %s", 501, "MAIL command must be immediately succeeded by 'FROM:'")
		}
		from := parts[1][5:]
		if !emailRegExp.MatchString(from) {
			return c.text.PrintfLine("%d %s", 501, "MAIL command contained invalid address")
		}
		email := emailRegExp.FindStringSubmatch(from)[1]
			if _, _, err := SplitAddress(email); err != nil && !strings.Contains(email, "@") {
		}
		c.mailFrom = email
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "RCPT":
		if c.mailFrom == "" {
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		if len(parts) < 2 {
			return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
		}
		if !strings.HasPrefix(parts[1], "TO:") {
			return c.text.PrintfLine("%d %s", 501, "RCPT command must be immediately succeeded by 'TO:'")
		}
		to := parts[1][3:]
		if !emailRegExp.MatchString(to) {
			return c.text.PrintfLine("%d %s", 501, "RCPT command contained invalid address")
		}
		email := emailRegExp.FindStringSubmatch(to)[1]

		if strings.ToLower(email) != "orb@pluto.onion" {
			return c.text.PrintfLine("%d %s", 550, "Only orb@pluto.onion is an allowed recipient for incoming mail.")
		}

		c.mailTo = append(c.mailTo, email)
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "DATA":
		if len(c.mailTo) == 0 || c.mailFrom == "" {
			return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
		}
		if err := c.text.PrintfLine("%d %s", 354, "End data with <CR><LF>.<CR><LF>"); err != nil {
			return err
		}
		data, err := c.text.ReadDotBytes()
		if err != nil {
			return err
		}
		c.mailData = bytes.NewBuffer(data)

		for _, recipient := range c.mailTo {
			if strings.ToLower(recipient) == "orb@pluto.onion" {
				env := &Envelope{
					FromAgent:           c.fromAgent,
					RemoteAddr:          c.remoteAddr,
					OriginalMessageFrom: c.mailFrom,
					MessageFrom:         RewriteFromAddress,
					MessageTo:           recipient,
					MessageData:         bytes.NewReader(c.mailData.Bytes()),
					ReceivedAt:          time.Now(),
					RetryCount:          0,
				}
				c.server.logf("INFO: Received ORB mail for orb@pluto.onion")
				if err := c.server.Handler.ServeSMTP(env); err != nil {
					c.server.logf("ERROR: Failed to handle ORB mail: %v", err)
					return c.text.PrintfLine("%d %s", 554, "Transaction failed (ORB processing error)")
				}
			} else {
				return c.text.PrintfLine("%d %s", 550, "Only orb@pluto.onion is an allowed recipient for incoming mail.")
			}
		}
		c.resetSession()
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "RSET":
		c.resetSession()
		return c.text.PrintfLine("%d %s", 250, "Ok")
	case "VRFY", "EXPN", "HELP", "NOOP":
		return c.text.PrintfLine("%d %s", 250, "OK")
	case "QUIT":
		c.quitSent = true
		return c.text.PrintfLine("%d %s", 221, "OK")
	default:
		return c.text.PrintfLine("%d %s", 500, "Command not recognized")
	}
}

func NewServeMux(srv *Server) *ServeMux {
	return &ServeMux{
		m:      make(map[string]map[string]muxEntry),
		server: srv,
	}
}

var DefaultServeMux *ServeMux

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
	parts := strings.SplitN(pattern, "@", 2)
	if len(parts) != 2 {
		log.Fatalf("invalid pattern format for ServeMux.Handle: %s", pattern)
	}
	localPart := CanonicalizeEmail(parts[0])
	if localPart == "" {
		localPart = "*"
	}
	domainPart := parts[1]
	if _, ok := mux.m[domainPart]; !ok {
		mux.m[domainPart] = make(map[string]muxEntry)
	}
	mux.m[domainPart][localPart] = muxEntry{h: handler, pattern: pattern}
}

func (mux *ServeMux) HandleFunc(pattern string, handler func(envelope *Envelope) error) {
	mux.Handle(pattern, HandlerFunc(handler))
}

func (mux *ServeMux) ServeSMTP(envelope *Envelope) error {
	if strings.ToLower(envelope.MessageTo) == "orb@pluto.onion" {
		localPart, domainPart, err := SplitAddress(envelope.MessageTo)
		if err != nil {
			return fmt.Errorf("invalid address for ORB handler: %w", err)
		}
		canonicalLocal := CanonicalizeEmail(localPart)
		mux.mu.RLock()
		defer mux.mu.RUnlock()

		if domainHandlers, ok := mux.m[domainPart]; ok {
			if handler, ok := domainHandlers[canonicalLocal]; ok {
				return handler.h.ServeSMTP(envelope)
			}
		}
	}
	return fmt.Errorf("no handler found for recipient %s (only orb@pluto.onion allowed)", envelope.MessageTo)
}

func createTorListener(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host != "127.0.0.1" && host != "localhost" {
		return nil, errors.New("server must listen on localhost for Tor hidden service")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &torListener{Listener: listener}, nil
}

func getConfigDir() (string, error) {
	var configDir string
	switch runtime.GOOS {
	case "windows":
		configDir = os.Getenv("APPDATA")
		if configDir == "" {
			return "", errors.New("APPDATA environment variable not set")
		}
		configDir = filepath.Join(configDir, "PlutoGo")
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "PlutoGo")
	default:
		configDir = filepath.Join(os.Getenv("HOME"), ".config", "plutogo")
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("could not create config directory: %v", err)
	}
	return configDir, nil
}

func ed25519PrivateKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if pk == nil || pk.Size() != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	h := sha512.New()
	h.Write(pk.Bytes()[:ed25519.SeedSize])
	out := h.Sum(nil)
	return memguard.NewBufferFromBytes(out[:curve25519.ScalarSize]), nil
}

func DecryptMinicrypt(ciphertext io.Reader, key *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if key == nil || key.Size() == 0 {
		return nil, errors.New("decryption requires a valid private key")
	}
	data, err := io.ReadAll(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("input could not be read: %w", err)
	}
	secureData := memguard.NewBufferFromBytes(data)
	defer secureData.Destroy()

	decoded, err := base64.StdEncoding.DecodeString(string(secureData.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %w", err)
	}
	const headerSize = curve25519.PointSize + chacha20poly1305.NonceSizeX
	if len(decoded) < headerSize {
		return nil, errors.New("message too short")
	}
	curvePriv, err := ed25519PrivateKeyToCurve25519(key)
	if err != nil {
		return nil, fmt.Errorf("private key conversion failed: %w", err)
	}
	defer curvePriv.Destroy()

	ephPub := decoded[:curve25519.PointSize]
	nonce := decoded[curve25519.PointSize:headerSize]
	ciphertextBytes := decoded[headerSize:]
	sharedSecret, err := curve25519.X25519(curvePriv.Bytes(), ephPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}
	secureSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSecret.Destroy()

	aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
	if err != nil {
		return nil, fmt.Errorf("decryption initialization failed: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	securePlaintext := memguard.NewBufferFromBytes(plaintext)

	for i := range plaintext {
		plaintext[i] = 0
	}

	return securePlaintext, nil
}

func (mux *ServeMux) handleORB(envelope *Envelope) error {
	if envelope.MessageData == nil {
		mux.server.logf("ERROR: MessageData is nil for ORB message.")
		return errors.New("message data is missing")
	}

	mailDataBytes, err := io.ReadAll(envelope.MessageData)
	if err != nil {
		mux.server.logf("ERROR: Failed to read raw ORB message data: %v", err)
		return fmt.Errorf("failed to read raw ORB message data: %w", err)
	}

	normalizedContent := regexp.MustCompile(`\r?\n`).ReplaceAllString(string(mailDataBytes), "\n")
	var originalBody string
	if bodySeparator := strings.Index(normalizedContent, "\n\n"); bodySeparator != -1 {
		originalBody = strings.TrimLeft(normalizedContent[bodySeparator+2:], " \t\n")
	} else {
		originalBody = normalizedContent
	}

	orbRegexp := regexp.MustCompile(`(?s)::([^:]+?)::`)
	match := orbRegexp.FindStringSubmatch(originalBody)
	if len(match) < 2 {
		return errors.New("ORB block not found or invalid format in message body")
	}
	orbBlockRaw := match[0]
	orbPayload := match[1]

	secureForwardAddressBuffer, err := DecryptMinicrypt(strings.NewReader(orbPayload), mux.server.MinicryptKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt ORB block: %w", err)
	}
	defer secureForwardAddressBuffer.Destroy()
	forwardAddress := strings.TrimSpace(string(secureForwardAddressBuffer.Bytes()))

	_, _, err = SplitAddress(forwardAddress)
	if err != nil {
		return fmt.Errorf("decrypted forward address '%s' is not a valid onion address: %w", forwardAddress, err)
	}

	cleanedBody := strings.Replace(originalBody, orbBlockRaw, "", 1)
	cleanedBody = regexp.MustCompile(`(?m)^[ \t]+`).ReplaceAllString(cleanedBody, "")
	cleanedBody = regexp.MustCompile(`\n{3,}`).ReplaceAllString(cleanedBody, "\n\n")
	cleanedBody = strings.TrimSpace(cleanedBody)

	var finalMessage bytes.Buffer
	finalMessage.WriteString(fmt.Sprintf("From: %s\r\n", RewriteFromAddress))
	finalMessage.WriteString(fmt.Sprintf("To: %s\r\n", forwardAddress))
	finalMessage.WriteString("\r\n")

	if cleanedBody != "" {
		finalMessage.WriteString(regexp.MustCompile(`\n`).ReplaceAllString(cleanedBody, "\r\n"))
	}

	forwardEnvelope := &Envelope{
		FromAgent:           envelope.FromAgent,
		RemoteAddr:          envelope.RemoteAddr,
		OriginalMessageFrom: envelope.OriginalMessageFrom,
		MessageFrom:         RewriteFromAddress,
		MessageTo:           forwardAddress,
		MessageData:         bytes.NewReader(finalMessage.Bytes()),
		ReceivedAt:          time.Now(),
		RetryCount:          0,
	}

	mux.server.logf("INFO: Forwarding mail from orb@pluto.onion to an ORB-encrypted onion address.")
	if !queueEnvelope(forwardEnvelope) {
		return errors.New("mail queue is full")
	}
	return nil
}

func smtpRelay(envelope *Envelope) error {
	_, domain, err := SplitAddress(envelope.MessageTo)
	if err != nil {
		return fmt.Errorf("invalid recipient address for relay: %w", err)
	}

	targetAddr := net.JoinHostPort(domain, "2525")
	dialer := &net.Dialer{Timeout: DeliveryTimeout}
	torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
	if err != nil {
		return fmt.Errorf("failed to create Tor dialer: %w", err)
	}
	conn, err := torDialer.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to relay target (%s): %w", targetAddr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(DeliveryTimeout))
	client, err := smtp.NewClient(conn, domain)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		}
		if err := client.StartTLS(cfg); err != nil {
			log.Printf("WARNING: Failed to STARTTLS with relay target %s: %v", domain, err)
		}
	}

	if err := client.Mail(RewriteFromAddress); err != nil {
		return fmt.Errorf("MAIL FROM failed (From: %s): %w", RewriteFromAddress, err)
	}

	if err := client.Rcpt(envelope.MessageTo); err != nil {
		return fmt.Errorf("RCPT TO failed (To: %s): %w", envelope.MessageTo, err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	defer wc.Close()

	if _, err := io.Copy(wc, envelope.MessageData); err != nil {
		return fmt.Errorf("message transfer failed: %w", err)
	}
	return nil
}

func queueEnvelope(envelope *Envelope) bool {
	mailQueueMutex.Lock()
	defer mailQueueMutex.Unlock()
	select {
	case mailQueue <- envelope:
		log.Printf("INFO: Mail queued for delivery.")
		return true
	default:
		return false
	}
}

func StartRelayWorkers(queue chan *Envelope, workerCount int) {
	for i := 0; i < workerCount; i++ {
		go func(id int) {
			log.Printf("INFO: Relay Worker %d started", id)
			for env := range queue {
				log.Printf("INFO: Worker %d: Processing mail.", id)
				err := smtpRelay(env)
				if err != nil {
					log.Printf("ERROR: Worker %d: Failed to deliver mail: %v", id, err)
					if env.RetryCount < 9 {
						env.RetryCount++
						time.Sleep(time.Duration(env.RetryCount) * 5 * time.Second)
						if !queueEnvelope(env) {
							log.Printf("WARNING: Worker %d: Failed to requeue message.", id)
						}
					} else {
						log.Printf("ERROR: Worker %d: Permanent failure after %d retries.", id, env.RetryCount)
					}
				} else {
					log.Printf("INFO: Worker %d: Successfully delivered mail.", id)
				}
			}
			log.Printf("INFO: Relay Worker %d stopped", id)
		}(i)
	}
}

func main() {
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		log.Fatal("Both -cert and -key flags are required")
	}
	var minicryptKey *memguard.LockedBuffer
	if *minicryptKeyFile != "" {
		pemData, err := os.ReadFile(*minicryptKeyFile)
		if err != nil {
			log.Fatalf("Failed to read minicrypt key: %v", err)
		}
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "PRIVATE KEY" {
			log.Fatal("Invalid minicrypt key format")
		}
		if len(block.Bytes) != ed25519.PrivateKeySize {
			log.Fatalf("Invalid minicrypt key size: expected %d, got %d", ed25519.PrivateKeySize, len(block.Bytes))
		}
		minicryptKey = memguard.NewBufferFromBytes(block.Bytes)
		log.Printf("INFO: Loaded minicrypt key from %s (%d bytes)", *minicryptKeyFile, minicryptKey.Size())
	} else {
		log.Fatal("Minicrypt key is required for ORB functionality (-mk flag).")
	}

	mailQueue = make(chan *Envelope, 100)
	StartRelayWorkers(mailQueue, RelayWorkerCount)

	server := &Server{
		Name:         "localhost",
		Addr:         "127.0.0.1:2525",
		Debug:        false,
		MinicryptKey: minicryptKey,
	}

	DefaultServeMux = NewServeMux(server)
	server.Handler = DefaultServeMux

	DefaultServeMux.HandleFunc("orb@pluto.onion", func(e *Envelope) error {
		return DefaultServeMux.handleORB(e)
	})

	listener, err := createTorListener(server.Addr)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	log.Printf("INFO: Starting SMTP server on %s", server.Addr)
	log.Printf("INFO: Using Tor proxy at %s", TorSocksProxyAddr)
	log.Printf("INFO: Started %d relay workers", RelayWorkerCount)
	log.Printf("INFO: Server is configured to only accept incoming mail for 'orb@pluto.onion' and relay to the address specified in the ORB block with strict header filtering.")

	if err := server.ServeTLS(listener); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
