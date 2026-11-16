package traffic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy is the HTTP proxy a phone sends its web requests through while an
// agent's task runs. Plain HTTP it passes on and keeps. HTTPS arrives as
// CONNECT: the proxy answers the TLS handshake with a certificate its CA
// signs for the host, reads the requests inside and passes them on over a
// new TLS connection that checks the server's own certificate. A phone
// that does not trust the CA, or an app that pins its certificate, refuses
// the handshake; the proxy then passes that host's connections through
// untouched for a while, as a tunnel it lists as not decrypted.
//
// It speaks HTTP/1.1 to the phone (it offers only http/1.1 in the
// handshake), and passes no WebSocket connections yet.
//
// It takes connections only from the addresses Client accepts, and serves
// the CA's certificate to them at CertPath, for the person to install, and
// a proxy auto-config file at PACPath. ListenSetup listens for those two
// files only, never proxying.
//
// Hosts Blocked names are never decrypted: their connections pass through
// as tunnels kept only as their host, marked blocked.
type Proxy struct {
	CA    *CA
	Store *Store
	// Client says which phone a connection from addr comes from, and
	// whether the proxy takes it at all. It is asked for each connection
	// and each request on it. nil takes none.
	Client func(addr netip.Addr) (device string, ok bool)
	// Record says whether to keep a phone's requests now: false while the
	// person holds the phone. The requests still go through. nil keeps all.
	Record func(device string) bool
	// Transport sends requests on; nil connects directly and checks the
	// servers' certificates.
	Transport http.RoundTripper
	// Dial connects the tunnels; nil dials directly.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Blocked says whether a phone's host is one Pinky never decrypts or
	// records beyond its host; nil blocks only BlockedHosts.
	Blocked func(device, host string) bool
	Log     *slog.Logger

	once sync.Once
	tr   http.RoundTripper

	mu        sync.Mutex
	listeners map[string]net.Listener
	// setupOnly: the listeners that serve only the setup files, to the
	// proxy address their PAC file names.
	setupOnly map[string]string
	conns     map[net.Conn]string // open connections, by the listener's address
	pinned    map[string]time.Time
	rejected  int
}

// Paths the proxy serves itself, to a phone that opens its address in a
// browser.
const (
	CertPath = "/pinky-ca.crt"
	pemPath  = "/pinky-ca.pem"
	// PACPath is the proxy auto-config file: the proxy, or a direct
	// connection when the proxy does not answer.
	PACPath = "/proxy.pac"
)

// Timeouts.
const (
	idleTimeout      = 2 * time.Minute
	handshakeTimeout = 15 * time.Second
	// pinnedFor is how long a host whose handshake failed passes through.
	pinnedFor = 10 * time.Minute
	pinnedMax = 4096
)

// Listen starts taking connections at addr ("192.168.1.5:9277", or
// "127.0.0.1:0" for any free port) and returns the address it listens at.
// Listening there already is not an error.
func (p *Proxy) Listen(addr string) (string, error) { return p.listen(addr, "") }

// ListenSetup starts serving only the setup files at addr: the CA's
// certificate and a PAC file that names proxy ("192.168.1.5:9277"). It
// proxies nothing and keeps nothing; it takes only the addresses Client
// accepts.
func (p *Proxy) ListenSetup(addr, proxy string) (string, error) { return p.listen(addr, proxy) }

func (p *Proxy) listen(addr, setupFor string) (string, error) {
	p.mu.Lock()
	if _, ok := p.listeners[addr]; ok {
		p.mu.Unlock()
		return addr, nil
	}
	p.mu.Unlock()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	at := ln.Addr().String()
	p.mu.Lock()
	if p.listeners == nil {
		p.listeners = map[string]net.Listener{}
		p.setupOnly = map[string]string{}
		p.conns = map[net.Conn]string{}
	}
	p.listeners[at] = ln
	if setupFor != "" {
		p.setupOnly[at] = setupFor
	}
	p.mu.Unlock()
	go p.accept(ln, at)
	return at, nil
}

// Stop stops listening at addr, and ends its open connections.
func (p *Proxy) Stop(addr string) {
	p.mu.Lock()
	ln := p.listeners[addr]
	delete(p.listeners, addr)
	delete(p.setupOnly, addr)
	var open []net.Conn
	for c, at := range p.conns {
		if at == addr {
			open = append(open, c)
		}
	}
	p.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range open {
		c.Close()
	}
}

// Addrs returns where the proxy listens.
func (p *Proxy) Addrs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.listeners))
	for a := range p.listeners {
		out = append(out, a)
	}
	return out
}

// Close stops listening everywhere.
func (p *Proxy) Close() {
	for _, a := range p.Addrs() {
		p.Stop(a)
	}
}

// Rejected returns how many connections came from addresses Client did not
// take.
func (p *Proxy) Rejected() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rejected
}

func (p *Proxy) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (p *Proxy) accept(ln net.Listener, at string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if _, ok := p.listeners[at]; !ok {
			p.mu.Unlock()
			c.Close()
			return
		}
		p.conns[c] = at
		p.mu.Unlock()
		go func() {
			defer func() {
				p.mu.Lock()
				delete(p.conns, c)
				p.mu.Unlock()
				c.Close()
			}()
			p.serve(c, at)
		}()
	}
}

// conn is who a connection came from.
type conn struct {
	device string
	client netip.Addr
}

// take says whether the proxy takes a connection from addr now.
func (p *Proxy) take(addr netip.Addr) (conn, bool) {
	if p.Client == nil {
		return conn{}, false
	}
	dev, ok := p.Client(addr.Unmap())
	return conn{device: dev, client: addr.Unmap()}, ok
}

func remoteAddr(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (p *Proxy) serve(c net.Conn, at string) {
	p.mu.Lock()
	setupFor, setupOnly := p.setupOnly[at]
	p.mu.Unlock()
	pac := at
	if setupOnly {
		pac = setupFor
	}
	cx, ok := p.take(remoteAddr(c))
	if !ok {
		p.mu.Lock()
		p.rejected++
		p.mu.Unlock()
		p.log().Info("traffic: refused a connection", "from", remoteAddr(c))
		return
	}
	br := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if _, ok := p.take(cx.client); !ok {
			return
		}
		switch {
		case setupOnly && (req.Method == http.MethodConnect || (req.URL.IsAbs() && !p.isSelf(hostPort(req.URL.Host, "80")))):
			// Outside a task this address hands out the setup files only.
			writeError(c, http.StatusForbidden, "Pinky's proxy runs only during an agent's task; this address serves only Pinky's setup files.")
			return
		case req.Method == http.MethodConnect:
			p.connect(c, br, req, cx)
			return
		case !req.URL.IsAbs() || p.isSelf(req.URL.Host):
			if !p.page(c, req, pac) {
				return
			}
		default:
			if req.URL.Host == "" {
				req.URL.Host = req.Host
			}
			if p.isSelf(hostPort(req.URL.Host, "80")) {
				if !p.page(c, req, pac) {
					return
				}
				continue
			}
			if !p.forward(c, req, cx, "", false) {
				return
			}
		}
	}
}

// hostPort adds port to a host without one.
func hostPort(hp, port string) string {
	if _, _, err := net.SplitHostPort(hp); err == nil {
		return hp
	}
	return net.JoinHostPort(strings.Trim(hp, "[]"), port)
}

// isSelf reports whether host:port is where the proxy listens, which it
// never passes requests on to.
func (p *Proxy) isSelf(hp string) bool {
	if hp == "" {
		return false
	}
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for a := range p.listeners {
		lh, lp, _ := net.SplitHostPort(a)
		if lp != port {
			continue
		}
		if lh == host || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return true
		}
	}
	return false
}

// page answers a request to the proxy itself: the CA's certificate, the
// PAC file naming the proxy at pac, or a page that links to the
// certificate. It returns whether the connection goes on.
func (p *Proxy) page(w io.Writer, req *http.Request, pac string) bool {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<16))
	}
	status, ctype, body := http.StatusOK, "text/html; charset=utf-8", []byte(nil)
	header := http.Header{}
	switch req.URL.Path {
	case CertPath:
		ctype, body = "application/x-x509-ca-cert", p.CA.CertDER()
		header.Set("Content-Disposition", `attachment; filename="pinky-ca.crt"`)
		// The person is installing the certificate: hosts that refused the
		// old trust get another chance.
		p.mu.Lock()
		p.pinned = nil
		p.mu.Unlock()
	case PACPath:
		ctype, body = "application/x-ns-proxy-autoconfig", []byte(PAC(pac))
	case pemPath:
		ctype, body = "application/x-pem-file", p.CA.CertPEM()
		header.Set("Content-Disposition", `attachment; filename="pinky-ca.pem"`)
	case "/", "":
		body = []byte(fmt.Sprintf(caPage, html.EscapeString(p.CA.Name()), CertPath, html.EscapeString(p.CA.Fingerprint())))
	default:
		status, ctype, body = http.StatusNotFound, "text/plain; charset=utf-8", []byte("Not found\n")
	}
	header.Set("Content-Type", ctype)
	header.Set("Cache-Control", "no-store")
	resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: header,
		ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Close: req.Close, Request: req}
	if req.Method == http.MethodHead {
		resp.Body = http.NoBody
	}
	return resp.Write(w) == nil && !req.Close
}

// PAC returns a proxy auto-config file that sends the phone's web
// requests to proxy, and connects directly when the proxy does not answer
// (outside an agent's task, or with Pinky not running). Names without a
// dot and .local ones always go directly.
func PAC(proxy string) string {
	return `function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".local")) {
    return "DIRECT";
  }
  return "PROXY ` + proxy + `; DIRECT";
}
`
}

const caPage = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pinky</title>
<style>body{font:17px -apple-system,system-ui,sans-serif;margin:2em auto;max-width:34em;padding:0 1em;line-height:1.5}a.b{display:inline-block;padding:.7em 1.2em;border-radius:.6em;background:#e8457a;color:#fff;text-decoration:none}code{word-break:break-all;font-size:13px}</style>
</head><body>
<h1>Pinky</h1>
<p>Install this certificate so that Pinky can read the web requests this phone makes during an agent's task. Pinky's window on the computer shows the steps.</p>
<p><a class="b" href="%[2]s">Download “%[1]s”</a></p>
<p>SHA-256: <code>%[3]s</code></p>
</body></html>
`

// forward passes one request on and its response back, and keeps both.
// target is where a decrypted request goes ("host:443"); "" for plain
// HTTP. It returns whether the connection goes on.
func (p *Proxy) forward(w io.Writer, req *http.Request, cx conn, target string, decrypted bool) bool {
	start := time.Now()
	keep := p.Record == nil || p.Record(cx.device)
	req.RequestURI = ""
	if decrypted {
		req.URL.Scheme, req.URL.Host = "https", target
	}
	host := req.URL.Hostname()
	if decrypted && req.Host != "" {
		host = hostOnly(req.Host)
	}
	if !decrypted && p.blocked(cx.device, host) {
		// Passed on, kept only as its host.
		if keep {
			defer p.keep(true, blockedRequest(cx, start, "http://"+host, host), Bodies{})
		}
		keep = false
	}
	r := Request{Device: cx.device, Client: cx.client, Start: start, Method: req.Method, Host: host, Decrypted: true}
	r.URL = displayURL(req, decrypted)
	r.Headers = headerList(req.Header)
	if req.Header.Get("Upgrade") != "" {
		r.End, r.Failed, r.Note = time.Now(), true, "a WebSocket or other upgrade, which Pinky's proxy does not pass on yet"
		writeError(w, http.StatusNotImplemented, "Pinky's proxy does not pass WebSocket connections on yet.")
		p.keep(keep, r, Bodies{})
		return false
	}
	if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		// The app waits for this before it sends the body.
		if _, err := io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return false
		}
		req.Header.Del("Expect")
	}
	clientClose := req.Close
	removeHop(req.Header)
	reqBody := &capture{}
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = &teeBody{ReadCloser: req.Body, c: reqBody}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := p.transport().RoundTrip(req.WithContext(ctx))
	if err != nil {
		r.End, r.Failed, r.Note = time.Now(), true, shortErr(err)
		r.Sent = reqBody.n
		writeError(w, http.StatusBadGateway, "Pinky's proxy could not reach the server: "+shortErr(err))
		p.keep(keep, r, Bodies{Request: reqBody.bytes(), RequestCut: reqBody.cut(), RequestType: req.Header.Get("Content-Type"),
			RequestEncoding: req.Header.Get("Content-Encoding")})
		return false
	}
	defer resp.Body.Close()
	removeHop(resp.Header)
	r.Status = resp.StatusCode
	r.ResponseHeaders = headerList(resp.Header)
	respBody := &capture{}
	resp.Body = &teeBody{ReadCloser: resp.Body, c: respBody}
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	resp.TransferEncoding = nil
	if resp.ContentLength < 0 && bodyAllowed(req.Method, resp.StatusCode) {
		resp.TransferEncoding = []string{"chunked"}
	}
	resp.Close = clientClose
	werr := resp.Write(w)
	r.End, r.Sent, r.Received = time.Now(), reqBody.n, respBody.n
	if werr != nil {
		r.Failed, r.Note = true, "the connection to the phone broke: "+shortErr(werr)
	}
	p.keep(keep, r, Bodies{
		Request: reqBody.bytes(), RequestCut: reqBody.cut(), RequestType: req.Header.Get("Content-Type"), RequestEncoding: req.Header.Get("Content-Encoding"),
		Response: respBody.bytes(), ResponseCut: respBody.cut(), ResponseType: resp.Header.Get("Content-Type"), ResponseEncoding: resp.Header.Get("Content-Encoding"),
	})
	return werr == nil && !clientClose
}

// blocked reports whether Pinky never decrypts or records a phone's host.
func (p *Proxy) blocked(device, host string) bool {
	if p.Blocked != nil {
		return p.Blocked(device, host)
	}
	return Blocked(host, nil)
}

// BlockedNote is the note of a blocked host's request.
const BlockedNote = "blocked: Pinky never decrypts or records this host"

// blockedRequest is all Pinky keeps of a request to a blocked host.
func blockedRequest(cx conn, start time.Time, url, host string) Request {
	return Request{Device: cx.device, Client: cx.client, Start: start, End: time.Now(), Method: http.MethodConnect,
		URL: url, Host: host, Blocked: true, Note: BlockedNote}
}

func (p *Proxy) keep(keep bool, r Request, b Bodies) {
	if keep && p.Store != nil {
		p.Store.Add(r, b)
	}
}

// displayURL is the URL as the app asked for it: the Host header's name,
// without the default port.
func displayURL(req *http.Request, decrypted bool) string {
	u := *req.URL
	if decrypted && req.Host != "" {
		h, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			h, port = req.Host, ""
		}
		if port == "" || port == "443" {
			u.Host = h
		} else {
			u.Host = req.Host
		}
	}
	if u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	} else {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	return u.String()
}

func hostOnly(hp string) string {
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return strings.Trim(hp, "[]")
}

func bodyAllowed(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

func writeError(w io.Writer, status int, msg string) {
	msg += "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Hop-by-hop headers, which a proxy does not pass on.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func headerList(h http.Header) []Header {
	var out []Header
	for name, vs := range h {
		for _, v := range vs {
			out = append(out, Header{Name: name, Value: v})
		}
	}
	sortHeaders(out)
	return out
}

func sortHeaders(hs []Header) {
	for i := 1; i < len(hs); i++ {
		for j := i; j > 0 && hs[j].Name < hs[j-1].Name; j-- {
			hs[j], hs[j-1] = hs[j-1], hs[j]
		}
	}
}

// capture keeps the first BodyMax bytes of a body, and counts them all.
type capture struct {
	buf bytes.Buffer
	n   int64
}

func (c *capture) Write(b []byte) {
	c.n += int64(len(b))
	if room := BodyMax + 1 - c.buf.Len(); room > 0 {
		if len(b) > room {
			b = b[:room]
		}
		c.buf.Write(b)
	}
}

func (c *capture) bytes() []byte {
	b := c.buf.Bytes()
	if len(b) > BodyMax {
		b = b[:BodyMax]
	}
	return bytes.Clone(b)
}

func (c *capture) cut() bool { return c.buf.Len() > BodyMax }

type teeBody struct {
	io.ReadCloser
	c *capture
}

func (t *teeBody) Read(b []byte) (int, error) {
	n, err := t.ReadCloser.Read(b)
	if n > 0 {
		t.c.Write(b[:n])
	}
	return n, err
}

func (p *Proxy) transport() http.RoundTripper {
	if p.Transport != nil {
		return p.Transport
	}
	p.once.Do(func() {
		p.tr = &http.Transport{
			Proxy:               nil, // never through another proxy, nor back through this one
			DialContext:         p.dial,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: handshakeTimeout,
			// Pass the app's own Accept-Encoding on, and the body as the
			// server sent it.
			DisableCompression: true,
		}
	})
	return p.tr
}

func (p *Proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.isSelf(addr) {
		return nil, errors.New("the request points back at Pinky's proxy")
	}
	if p.Dial != nil {
		return p.Dial(ctx, network, addr)
	}
	d := net.Dialer{Timeout: handshakeTimeout}
	return d.DialContext(ctx, network, addr)
}

// connect answers CONNECT: it decrypts the connection when the phone
// accepts the CA's certificate for the host, and passes it through
// untouched otherwise.
func (p *Proxy) connect(c net.Conn, br *bufio.Reader, req *http.Request, cx conn) {
	target := hostPort(req.Host, "443")
	host, port, _ := net.SplitHostPort(target)
	if p.isSelf(target) {
		writeError(c, http.StatusForbidden, "That is Pinky's proxy itself.")
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	start := time.Now()
	keep := p.Record == nil || p.Record(cx.device)
	if p.blocked(cx.device, host) {
		p.tunnel(c, br, target, host, cx, start, false, "")
		p.keep(keep, blockedRequest(cx, start, "https://"+host, host), Bodies{})
		return
	}
	if p.isPinned(host) {
		p.tunnel(c, br, target, host, cx, start, keep, "passed through: this host refused Pinky's certificate earlier")
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 0x16 { // not a TLS handshake
		_ = c.SetReadDeadline(time.Time{})
		p.tunnel(c, br, target, host, cx, start, keep, "passed through: not TLS")
		return
	}
	sni := ""
	tc := tls.Server(&bufConn{Conn: c, r: br}, &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = h.ServerName
			name := sni
			if name == "" {
				name = host
			}
			return p.CA.Leaf(name)
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err = tc.HandshakeContext(ctx)
	cancel()
	refused := func(why string) {
		p.pin(host)
		p.keep(keep, Request{Device: cx.device, Client: cx.client, Start: start, End: time.Now(), Method: http.MethodConnect,
			URL: "https://" + target, Host: host, Failed: true, Note: why}, Bodies{})
	}
	if err != nil {
		refused("the phone refused Pinky's certificate (it is not trusted there, or the app pins its own); this host passes through without decryption for a while")
		return
	}
	name := host
	if sni != "" {
		name = sni
	}
	upstream := net.JoinHostPort(name, port)
	tbr := bufio.NewReader(tc)
	served := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		r, err := http.ReadRequest(tbr)
		if err != nil {
			if served == 0 && !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
				// An app that checks the certificate itself after the
				// handshake hangs up without a request.
				refused("the app hung up after the handshake, as one that pins its certificate does; this host passes through without decryption for a while")
			}
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if _, ok := p.take(cx.client); !ok {
			return
		}
		served++
		if !p.forward(tc, r, cx, upstream, true) {
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// bufConn is a connection whose first bytes wait in a bufio.Reader.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (p *Proxy) pin(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pinned == nil || len(p.pinned) >= pinnedMax {
		p.pinned = map[string]time.Time{}
	}
	p.pinned[strings.ToLower(host)] = time.Now().Add(pinnedFor)
}

func (p *Proxy) isPinned(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.pinned[strings.ToLower(host)]
	return ok && time.Now().Before(until)
}

// Pinned lists the hosts that pass through now.
func (p *Proxy) Pinned() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for h, until := range p.pinned {
		if time.Now().Before(until) {
			out = append(out, h)
		}
	}
	return out
}

// tunnel passes a connection through untouched, and keeps it as one
// request that was not decrypted.
func (p *Proxy) tunnel(c net.Conn, br *bufio.Reader, target, host string, cx conn, start time.Time, keep bool, note string) {
	r := Request{Device: cx.device, Client: cx.client, Start: start, Method: http.MethodConnect,
		URL: "https://" + target, Host: host, Note: note}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	up, err := p.dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		r.End, r.Failed, r.Note = time.Now(), true, shortErr(err)
		p.keep(keep, r, Bodies{})
		return
	}
	defer up.Close()
	var sent, recv int64
	done := make(chan struct{}, 2)
	go func() {
		sent, _ = io.Copy(up, br)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		recv, _ = io.Copy(c, up)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// One side is done; give the other a moment to finish.
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = up.SetDeadline(time.Now().Add(5 * time.Second))
	<-done
	r.End, r.Sent, r.Received = time.Now(), sent, recv
	p.keep(keep, r, Bodies{})
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// Port returns the port of an address Listen returned.
func Port(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
