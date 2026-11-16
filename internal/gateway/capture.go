package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/DIYgod/pinky/internal/driver"
	"github.com/DIYgod/pinky/internal/history"
	"github.com/DIYgod/pinky/internal/traffic"
)

// Pinky's own traffic capture (docs/notes/traffic-capture.md): one HTTP
// proxy on the computer (traffic.Proxy), listening only while a phone
// whose Read network traffic switch is on runs a task (or the person has
// its setup open), only on the address that phone reaches, and taking
// connections only from that phone's own addresses. What it sees stays in
// memory (traffic.Store) and is dropped when the task ends.
//
// The phone reaches it in one of two ways:
//
//   - The person sets the phone's Wi-Fi HTTP proxy to the address Pinky
//     shows (iPhone, Android). Pinky learns the phone's address from its
//     connection (driver.NetAddresser) and listens on this computer's
//     address on the same network.
//   - Android only, when the person turns on Route through Pinky during
//     tasks: Pinky has the phone's 127.0.0.1:port reach the computer over
//     adb (adb reverse) and sets the phone's global HTTP proxy to it for
//     the task (driver.ProxyRouter). It notes the setting it found first
//     (history traffic_routes) and puts it back when the task ends, the
//     switch goes off, the phone is removed, Pinky stops, and at the next
//     start after a crash. Never through an agent tool.

// TrafficPort is the port Pinky's proxy listens at, unless
// Options.TrafficPort says another.
const TrafficPort = 9277

// Why a phone's traffic is not being captured (TrafficSetup.Problem).
const (
	// TrafficNoAddress: Pinky knows no address of the phone on a network
	// this computer is on (an iPhone on its cable only, a phone on mobile
	// data), and the phone is not routed over its cable.
	TrafficNoAddress = "no_address"
	// TrafficListenFailed: the port is taken on this computer.
	TrafficListenFailed = "listen_failed"
	// TrafficNoCA: the certificate authority could not be read or made.
	TrafficNoCA = "no_ca"
	// TrafficRouteFailed: setting the Android phone's proxy failed.
	TrafficRouteFailed = "route_failed"
	// TrafficRouteBusy: another phone is routed through its cable already;
	// one at a time.
	TrafficRouteBusy = "route_busy"
)

// captureState is the gateway's capture. Its lock is taken after g.mu,
// never before.
type captureState struct {
	store *traffic.Store
	kick  chan struct{}
	// syncMu makes sync passes take turns.
	syncMu sync.Mutex

	mu      sync.Mutex
	ca      *traffic.CA
	proxy   *traffic.Proxy
	caErr   error
	clients map[netip.Addr]string // the phones' addresses, to their ids
	routed  string                // the phone that reaches the proxy over adb reverse, at 127.0.0.1
	listen  map[string][]string   // by phone: the addresses it should use as its proxy
	problem map[string]string     // by phone: why nothing listens for it
	hidden  map[string]int        // by phone: requests left out while the person held it
	setup   map[string]bool       // phones whose setup the person has open
	routes  map[string]liveRoute  // routes made in this run
	pending []history.TrafficRoute
	addrs   map[string]addrSeen
}

type liveRoute struct {
	history.TrafficRoute
	router driver.ProxyRouter
}

type addrSeen struct {
	addrs []netip.Addr
	at    time.Time
}

// addrFresh is how long a phone's addresses are taken as they were read.
const addrFresh = 30 * time.Second

func (g *Gateway) initCapture() {
	g.cap.store = traffic.NewStore(0, 0)
	g.cap.kick = make(chan struct{}, 1)
	g.cap.clients = map[netip.Addr]string{}
	g.cap.listen = map[string][]string{}
	g.cap.problem = map[string]string{}
	g.cap.hidden = map[string]int{}
	g.cap.setup = map[string]bool{}
	g.cap.routes = map[string]liveRoute{}
	g.cap.addrs = map[string]addrSeen{}
	if g.store != nil {
		// Settings a Pinky that crashed left on phones, to put back.
		if rs, err := g.store.TrafficRoutes(context.Background()); err == nil {
			g.cap.pending = rs
		} else {
			g.log.Warn("history: traffic routes", "err", err)
		}
	}
}

func (g *Gateway) trafficPort() int {
	if g.opt.TrafficPort > 0 {
		return g.opt.TrafficPort
	}
	return TrafficPort
}

// captureSoon asks the capture loop to look again now.
func (g *Gateway) captureSoon() {
	select {
	case g.cap.kick <- struct{}{}:
	default:
	}
}

func (g *Gateway) captureLoop() {
	defer g.wg.Done()
	every := 5 * g.opt.DiscoverEvery
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
		case <-g.cap.kick:
		}
		ctx, cancel := context.WithTimeout(g.ctx, 20*time.Second)
		g.syncCapture(ctx)
		cancel()
	}
}

// proxyLocked returns the proxy, making it and loading the certificate
// authority the first time. The caller holds g.cap.mu.
func (g *Gateway) proxyLocked() (*traffic.Proxy, error) {
	c := &g.cap
	if c.proxy != nil {
		return c.proxy, nil
	}
	if c.ca == nil {
		ca := g.opt.TrafficCA
		var err error
		switch {
		case ca != nil:
		case g.opt.DataDir != "":
			ca, err = traffic.LoadCA(filepath.Clean(g.opt.DataDir))
		default:
			ca, err = traffic.NewCA()
		}
		if err != nil {
			c.caErr = err
			return nil, err
		}
		c.ca, c.caErr = ca, nil
	}
	c.proxy = &traffic.Proxy{CA: c.ca, Store: c.store, Client: g.trafficClient, Record: g.recordTraffic,
		Transport: g.opt.TrafficTransport, Log: g.log}
	return c.proxy, nil
}

// trafficClient is the proxy's Client: the phone at addr, if a phone
// being captured is there.
func (g *Gateway) trafficClient(addr netip.Addr) (string, bool) {
	g.cap.mu.Lock()
	defer g.cap.mu.Unlock()
	if id, ok := g.cap.clients[addr]; ok {
		return id, true
	}
	if addr.IsLoopback() && g.cap.routed != "" {
		return g.cap.routed, true
	}
	return "", false
}

// recordTraffic is the proxy's Record: a phone's requests are kept while
// its task runs, and not while the person holds it.
func (g *Gateway) recordTraffic(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.devices[id]
	if d == nil || d.lease == nil || d.lease.ended || !g.trafficOn[id] {
		return false
	}
	if d.quietWhy != 0 {
		g.cap.mu.Lock()
		g.cap.hidden[id]++
		g.cap.mu.Unlock()
		return false
	}
	return true
}

// dropTraffic forgets what was captured of a phone. Callers may hold g.mu.
func (g *Gateway) dropTraffic(id string) {
	g.cap.store.Drop(id)
	g.cap.mu.Lock()
	delete(g.cap.hidden, id)
	g.cap.mu.Unlock()
}

// captureWant is one phone the capture is for.
type captureWant struct {
	id       string
	provider driver.Provider
	route    bool // through its cable, by the person's switch
}

// syncCapture opens and closes the proxy's listeners and the Android
// routes for what runs now.
func (g *Gateway) syncCapture(ctx context.Context) {
	g.cap.syncMu.Lock()
	defer g.cap.syncMu.Unlock()
	var want []captureWant
	g.mu.Lock()
	if !g.closed {
		g.cap.mu.Lock()
		for id, d := range g.devices {
			if !g.trafficOn[id] || d.dev == nil {
				continue
			}
			running := d.lease != nil && !d.lease.ended
			if !running && !g.cap.setup[id] {
				continue
			}
			want = append(want, captureWant{id: id, provider: d.provider, route: running && g.trafficRoute[id]})
		}
		g.cap.mu.Unlock()
	}
	g.mu.Unlock()
	slices.SortFunc(want, func(a, b captureWant) int {
		switch {
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		}
		return 0
	})

	g.restorePending(ctx)
	port := g.trafficPort()

	// Routes no longer wanted go back first.
	g.cap.mu.Lock()
	var undo []liveRoute
	for id, r := range g.cap.routes {
		if !slices.ContainsFunc(want, func(w captureWant) bool { return w.id == id && w.route }) {
			undo = append(undo, r)
		}
	}
	g.cap.mu.Unlock()
	for _, r := range undo {
		g.unroute(ctx, r)
	}

	if len(want) == 0 {
		g.cap.mu.Lock()
		if p := g.cap.proxy; p != nil {
			p.Close()
		}
		clear(g.cap.clients)
		clear(g.cap.listen)
		clear(g.cap.problem)
		g.cap.routed = ""
		g.cap.mu.Unlock()
		return
	}

	g.cap.mu.Lock()
	p, err := g.proxyLocked()
	g.cap.mu.Unlock()
	if err != nil {
		g.log.Warn("traffic: certificate authority", "err", err)
		g.cap.mu.Lock()
		for _, w := range want {
			g.cap.problem[w.id] = TrafficNoCA
		}
		g.cap.mu.Unlock()
		return
	}

	locals, err := g.localPrefixes()
	if err != nil {
		g.log.Warn("traffic: this computer's addresses", "err", err)
	}
	clients := map[netip.Addr]string{}
	listen := map[string][]string{}
	problem := map[string]string{}
	keep := map[string]bool{}
	for _, w := range want {
		for _, a := range g.phoneAddrs(ctx, w) {
			ip, ok := listenAddr(a, locals)
			if !ok {
				continue
			}
			at := net.JoinHostPort(ip.String(), strconv.Itoa(port))
			if _, err := p.Listen(at); err != nil {
				g.log.Warn("traffic: listen", "addr", at, "err", err)
				problem[w.id] = TrafficListenFailed
				continue
			}
			keep[at] = true
			clients[a] = w.id
			if !slices.Contains(listen[w.id], at) {
				listen[w.id] = append(listen[w.id], at)
			}
		}
		if w.route {
			if why := g.route(ctx, p, w, port); why != "" {
				problem[w.id] = why
			} else {
				keep[net.JoinHostPort("127.0.0.1", strconv.Itoa(port))] = true
			}
		}
		if len(listen[w.id]) == 0 && problem[w.id] == "" && !w.route {
			problem[w.id] = TrafficNoAddress
		}
	}
	for _, at := range p.Addrs() {
		if !keep[at] {
			p.Stop(at)
		}
	}
	g.cap.mu.Lock()
	g.cap.clients, g.cap.listen, g.cap.problem = clients, listen, problem
	g.cap.mu.Unlock()
}

// phoneAddrs returns a phone's addresses, read again when they are old.
func (g *Gateway) phoneAddrs(ctx context.Context, w captureWant) []netip.Addr {
	na, ok := w.provider.(driver.NetAddresser)
	if !ok {
		return nil
	}
	g.cap.mu.Lock()
	seen, ok := g.cap.addrs[w.id]
	g.cap.mu.Unlock()
	if ok && time.Since(seen.at) < addrFresh {
		return seen.addrs
	}
	addrs, err := na.PhoneAddrs(ctx, w.id)
	if err != nil {
		g.log.Debug("traffic: the phone's addresses", "device", w.id, "err", err)
	}
	g.cap.mu.Lock()
	g.cap.addrs[w.id] = addrSeen{addrs: addrs, at: time.Now()}
	g.cap.mu.Unlock()
	return addrs
}

// route points an Android phone's proxy at Pinky over its cable, once
// per task. It returns why it could not.
func (g *Gateway) route(ctx context.Context, p *traffic.Proxy, w captureWant, port int) string {
	pr, ok := w.provider.(driver.ProxyRouter)
	if !ok {
		return TrafficRouteFailed
	}
	g.cap.mu.Lock()
	_, done := g.cap.routes[w.id]
	other := g.cap.routed != "" && g.cap.routed != w.id
	g.cap.mu.Unlock()
	if done {
		return ""
	}
	if other {
		return TrafficRouteBusy
	}
	at := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if _, err := p.Listen(at); err != nil {
		g.log.Warn("traffic: listen", "addr", at, "err", err)
		return TrafficListenFailed
	}
	prev, err := pr.ProxySetting(ctx, w.id)
	if err != nil {
		g.log.Warn("traffic: read the phone's proxy", "device", w.id, "err", err)
		return TrafficRouteFailed
	}
	r := history.TrafficRoute{DeviceID: w.id, Prev: prev, Port: port}
	// Noted before the phone changes, so that a crash in between still
	// puts it back.
	if g.store != nil {
		if err := g.store.SaveTrafficRoute(ctx, r); err != nil {
			g.log.Warn("history: traffic route", "err", err)
			return TrafficRouteFailed
		}
	}
	if err := pr.RouteProxy(ctx, w.id, port); err != nil {
		g.log.Warn("traffic: route the phone", "device", w.id, "err", err)
		g.unroute(ctx, liveRoute{TrafficRoute: r, router: pr})
		return TrafficRouteFailed
	}
	g.log.Info("traffic: routed the phone through Pinky", "device", w.id, "port", port)
	g.cap.mu.Lock()
	g.cap.routes[w.id] = liveRoute{TrafficRoute: r, router: pr}
	g.cap.routed = w.id
	g.cap.mu.Unlock()
	return ""
}

// unroute puts a phone's proxy setting back. When the phone cannot be
// reached the route stays saved, and the next pass (or start) tries again.
func (g *Gateway) unroute(ctx context.Context, r liveRoute) {
	err := r.router.UnrouteProxy(ctx, r.DeviceID, r.Port, r.Prev)
	g.cap.mu.Lock()
	delete(g.cap.routes, r.DeviceID)
	if g.cap.routed == r.DeviceID {
		g.cap.routed = ""
	}
	if err != nil {
		g.cap.pending = append(g.cap.pending, r.TrafficRoute)
	}
	g.cap.mu.Unlock()
	if err != nil {
		g.log.Warn("traffic: put the phone's proxy back", "device", r.DeviceID, "err", err)
		return
	}
	g.log.Info("traffic: put the phone's proxy back", "device", r.DeviceID)
	if g.store != nil {
		if err := g.store.DeleteTrafficRoute(ctx, r.DeviceID); err != nil {
			g.log.Warn("history: traffic route", "err", err)
		}
	}
}

// restorePending puts back the settings of routes an earlier run (or a
// phone that was away) left, through whichever provider reaches the phone.
func (g *Gateway) restorePending(ctx context.Context) {
	g.cap.mu.Lock()
	pending := g.cap.pending
	g.cap.pending = nil
	g.cap.mu.Unlock()
	var left []history.TrafficRoute
	for _, r := range pending {
		done := false
		for _, p := range g.opt.Providers {
			pr, ok := p.(driver.ProxyRouter)
			if !ok {
				continue
			}
			if err := pr.UnrouteProxy(ctx, r.DeviceID, r.Port, r.Prev); err == nil {
				done = true
				break
			}
		}
		if !done {
			left = append(left, r)
			continue
		}
		g.log.Info("traffic: put back a phone's proxy from before", "device", r.DeviceID)
		if g.store != nil {
			if err := g.store.DeleteTrafficRoute(ctx, r.DeviceID); err != nil {
				g.log.Warn("history: traffic route", "err", err)
			}
		}
	}
	g.cap.mu.Lock()
	g.cap.pending = append(left, g.cap.pending...)
	g.cap.mu.Unlock()
}

// stopCapture ends the capture as Pinky stops: listeners close and the
// phones' settings go back.
func (g *Gateway) stopCapture() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g.syncCapture(ctx)
}

// localPrefixes returns this computer's addresses with their networks.
func (g *Gateway) localPrefixes() ([]netip.Prefix, error) {
	if g.opt.TrafficInterfaces != nil {
		return g.opt.TrafficInterfaces()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return out, nil
}

// Tailscale's ranges: a computer's own Tailscale address is a /32 (or
// /128), so a phone on the tailnet is matched by the range.
var tailnets = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

// listenAddr picks this computer's address on the network a phone at a is
// on: the one whose network holds a, or for a phone on Tailscale this
// computer's Tailscale address. Never a link-local address.
func listenAddr(a netip.Addr, locals []netip.Prefix) (netip.Addr, bool) {
	a = a.Unmap()
	if a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return netip.Addr{}, false
	}
	for _, t := range tailnets {
		if !t.Contains(a) {
			continue
		}
		for _, l := range locals {
			if t.Contains(l.Addr()) && l.Addr().Is4() == a.Is4() {
				return l.Addr(), true
			}
		}
		return netip.Addr{}, false
	}
	for _, l := range locals {
		if l.Addr().IsLinkLocalUnicast() || l.Addr().IsLoopback() != a.IsLoopback() {
			continue
		}
		if l.Masked().Contains(a) {
			return l.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// TrafficSetup is what the person needs to point a phone at Pinky's proxy
// and trust its certificate, for Settings › Phones.
type TrafficSetup struct {
	// Proxies are the addresses ("192.168.1.5:9277") the phone sets as its
	// HTTP proxy; empty while nothing listens for it.
	Proxies []string
	// CertURL is where the phone's browser downloads the certificate, at
	// the first proxy address.
	CertURL     string
	CAName      string
	Fingerprint string
	// CanRoute: an Android phone Pinky can route through its cable.
	CanRoute bool
	// Route is the person's switch, Routed whether the phone's proxy is set
	// to Pinky now.
	Route, Routed bool
	// Problem is why nothing listens for it, one of the Traffic*
	// constants; "" when all is well or nothing should listen.
	Problem string
}

// TrafficSetup returns how a phone reaches Pinky's proxy now.
func (g *Gateway) TrafficSetup(deviceID string) (TrafficSetup, error) {
	d, err := g.device(deviceID)
	if err != nil {
		return TrafficSetup{}, err
	}
	g.mu.Lock()
	_, can := d.provider.(driver.ProxyRouter)
	s := TrafficSetup{CanRoute: can, Route: g.trafficRoute[d.id]}
	g.mu.Unlock()
	g.cap.mu.Lock()
	defer g.cap.mu.Unlock()
	s.Proxies = slices.Clone(g.cap.listen[d.id])
	s.Problem = g.cap.problem[d.id]
	_, s.Routed = g.cap.routes[d.id]
	if s.Problem == "" && g.cap.caErr != nil {
		s.Problem = TrafficNoCA
	}
	if g.cap.ca != nil {
		s.CAName, s.Fingerprint = g.cap.ca.Name(), g.cap.ca.Fingerprint()
	}
	if len(s.Proxies) > 0 {
		s.CertURL = "http://" + s.Proxies[0] + traffic.CertPath
	}
	return s, nil
}

// ServeTrafficCA keeps the proxy listening for a phone while the person
// has its setup open (on), so that its browser can download the
// certificate; requests are kept only while a task runs. It applies
// shortly; TrafficSetup says the result.
func (g *Gateway) ServeTrafficCA(deviceID string, on bool) error {
	d, err := g.device(deviceID)
	if err != nil {
		return err
	}
	g.cap.mu.Lock()
	if on {
		g.cap.setup[d.id] = true
	} else {
		delete(g.cap.setup, d.id)
	}
	g.cap.mu.Unlock()
	g.captureSoon()
	return nil
}

// ErrTrafficOff is returned when a phone's traffic switch is off.
var ErrTrafficOff = errors.New("reading this phone's network traffic is off")

// SetTrafficRoute sets whether Pinky points an Android phone's HTTP proxy
// at itself during tasks, over its cable. Only the person turns it on, in
// Settings › Phones; it needs Read network traffic on, and is saved per
// phone. Turning it off puts the phone's setting back now.
func (g *Gateway) SetTrafficRoute(deviceID string, on bool) error {
	d, err := g.device(deviceID)
	if err != nil {
		return err
	}
	g.mu.Lock()
	if _, ok := d.provider.(driver.ProxyRouter); !ok && on {
		g.mu.Unlock()
		return driver.ErrUnsupported
	}
	if on && !g.trafficOn[d.id] {
		g.mu.Unlock()
		return ErrTrafficOff
	}
	if on {
		g.trafficRoute[d.id] = true
	} else {
		delete(g.trafficRoute, d.id)
	}
	if g.store != nil {
		id := d.id
		g.rec.do(func(ctx context.Context) error { return g.store.SetDeviceTrafficRoute(ctx, id, on) })
	}
	g.mu.Unlock()
	g.captureSoon()
	g.emit(Event{Kind: EventDevices, DeviceID: d.id})
	return nil
}

// TrafficRoute reports the person's route switch for a phone.
func (g *Gateway) TrafficRoute(deviceID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.trafficRoute[deviceID]
}

// trafficListening says where the proxy listens for a phone, and why not.
func (g *Gateway) trafficListening(id string) (addrs []string, routed bool, problem string) {
	g.cap.mu.Lock()
	defer g.cap.mu.Unlock()
	_, routed = g.cap.routes[id]
	return slices.Clone(g.cap.listen[id]), routed, g.cap.problem[id]
}
