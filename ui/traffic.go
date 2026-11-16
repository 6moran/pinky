package ui

import (
	"net"
	"strconv"
	"time"

	mg "github.com/egoist/mygo/ui"

	"github.com/DIYgod/pinky/cmd/pinky/locales"
	"github.com/DIYgod/pinky/internal/driver"
	"github.com/DIYgod/pinky/internal/gateway"
)

// Read network traffic (docs/notes/traffic-capture.md): a switch per phone
// in Settings › Phones, off by default, that lets agents read the web
// requests the phone makes during their tasks (phone_traffic), through
// Pinky's own proxy. With it on, the person can open the phone's setup:
// the proxy's address, Pinky's certificate and the steps on the phone, and
// on Android the switch that routes the phone through its cable.

// trafficSetter is the gateway's part of it.
type trafficSetter interface {
	SetTraffic(deviceID string, on bool) error
	Traffic(deviceID string) bool
}

// trafficSetuper is the gateway's part of the setup.
type trafficSetuper interface {
	TrafficSetup(deviceID string) (gateway.TrafficSetup, error)
	ServeTrafficCA(deviceID string, on bool) error
	SetTrafficRoute(deviceID string, on bool) error
}

// trafficEvery is how often an open setup reads the gateway again: where
// the proxy listens follows the phone's networks, which send no event.
const trafficEvery = 2 * time.Second

// trafficState is the switch's part of the client.
type trafficState struct {
	on   map[string]bool // Traffic(id), read with the devices
	busy map[string]bool // a SetTraffic is under way
	// open: the person has the phone's setup open, so the proxy listens
	// for it to serve the certificate.
	open    map[string]bool
	setup   map[string]gateway.TrafficSetup
	at      map[string]time.Time // when setup was read
	loading map[string]bool
	routing map[string]bool // a SetTrafficRoute is under way
}

func (s *trafficState) init() {
	if s.on == nil {
		*s = trafficState{on: map[string]bool{}, busy: map[string]bool{}, open: map[string]bool{},
			setup: map[string]gateway.TrafficSetup{}, at: map[string]time.Time{}, loading: map[string]bool{},
			routing: map[string]bool{}}
	}
}

// readTraffic asks the gateway which phones' traffic agents may read, off
// the main thread, as Devices is read.
func (a *app) readTraffic(devs []gateway.DeviceView) map[string]bool {
	ts, ok := a.api.(trafficSetter)
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, d := range devs {
		out[d.Info.ID] = ts.Traffic(d.Info.ID)
	}
	return out
}

// setTraffics takes what readTraffic read.
func (a *app) setTraffics(on map[string]bool) {
	a.traffic.init()
	for id, v := range on {
		if !a.traffic.busy[id] {
			a.traffic.on[id] = v
			if !v {
				a.closeTrafficSetup(id)
			}
		}
	}
}

// forgetTraffic drops what the client keeps of a removed phone.
func (a *app) forgetTraffic(id string) {
	a.closeTrafficSetup(id)
	for _, m := range []map[string]bool{a.traffic.on, a.traffic.busy, a.traffic.loading, a.traffic.routing} {
		delete(m, id)
	}
	delete(a.traffic.setup, id)
	delete(a.traffic.at, id)
}

// setTraffic turns reading a phone's traffic on or off.
func (a *app) setTraffic(d gateway.DeviceView, on bool) {
	ts, ok := a.api.(trafficSetter)
	id, name := d.Info.ID, d.Info.Name
	if !ok || a.traffic.busy[id] {
		return
	}
	a.traffic.init()
	a.traffic.on[id], a.traffic.busy[id] = on, true
	if !on {
		a.closeTrafficSetup(id)
	}
	go func() {
		err := ts.SetTraffic(id, on)
		now := ts.Traffic(id) // what the gateway kept, after an error too
		a.post(func() {
			a.traffic.busy[id], a.traffic.on[id] = false, now
			if err != nil {
				a.toasts = append(a.toasts, locales.TrafficChangeFailed(name, err.Error()))
			}
		})
	}()
}

// openTrafficSetup shows a phone's setup and keeps the proxy listening for
// it meanwhile.
func (a *app) openTrafficSetup(id string) {
	ts, ok := a.api.(trafficSetuper)
	if !ok || a.traffic.open[id] {
		return
	}
	a.traffic.open[id] = true
	delete(a.traffic.at, id) // read it now
	go ts.ServeTrafficCA(id, true)
}

// closeTrafficSetup hides it; the proxy then listens only during tasks.
func (a *app) closeTrafficSetup(id string) {
	ts, ok := a.api.(trafficSetuper)
	if !ok || !a.traffic.open[id] {
		return
	}
	delete(a.traffic.open, id)
	go ts.ServeTrafficCA(id, false)
}

// trafficSetupOf reads a phone's setup off the main thread, again every
// trafficEvery while it shows.
func (a *app) trafficSetupOf(c *mg.Context, id string) (gateway.TrafficSetup, bool) {
	ts, ok := a.api.(trafficSetuper)
	if !ok {
		return gateway.TrafficSetup{}, false
	}
	s := &a.traffic
	if !s.loading[id] && time.Since(s.at[id]) >= trafficEvery {
		s.loading[id] = true
		go func() {
			st, err := ts.TrafficSetup(id)
			a.post(func() {
				s.loading[id], s.at[id] = false, time.Now()
				if err == nil {
					s.setup[id] = st
				} else {
					delete(s.setup, id)
				}
			})
		}()
	}
	c.After(trafficEvery)
	st, have := s.setup[id]
	return st, have
}

// setTrafficRoute turns routing an Android phone through its cable on or
// off.
func (a *app) setTrafficRoute(d gateway.DeviceView, on bool) {
	ts, ok := a.api.(trafficSetuper)
	id, name := d.Info.ID, d.Info.Name
	if !ok || a.traffic.routing[id] {
		return
	}
	a.traffic.routing[id] = true
	if st, have := a.traffic.setup[id]; have {
		st.Route = on
		a.traffic.setup[id] = st
	}
	go func() {
		err := ts.SetTrafficRoute(id, on)
		st, serr := ts.TrafficSetup(id)
		a.post(func() {
			a.traffic.routing[id] = false
			if serr == nil {
				a.traffic.setup[id], a.traffic.at[id] = st, time.Now()
			}
			if err != nil {
				a.toasts = append(a.toasts, locales.TrafficRouteChangeFailed(name, err.Error()))
			}
		})
	}()
}

// trafficRow is the "Read network traffic" switch with its words, and,
// with it on, the phone's setup.
func (a *app) trafficRow(c *mg.Context, d gateway.DeviceView, last bool) {
	if _, ok := a.api.(trafficSetter); !ok {
		return
	}
	a.traffic.init()
	id := d.Info.ID
	on := a.traffic.on[id]
	if a.toggleRowFor(c, "traffic-"+id, locales.TrafficTitle(), locales.TrafficDesc(), last && !on, &on) {
		a.setTraffic(d, on)
	}
	if !on {
		return
	}
	if _, ok := a.api.(trafficSetuper); !ok {
		return
	}
	open := a.traffic.open[id]
	settingRow(c, locales.TrafficSetupTitle(), locales.TrafficSetupDesc(), last && !open, func() {
		label := locales.TrafficSetupShow()
		if open {
			label = locales.TrafficSetupHide()
		}
		if button(c.Key("traffic-setup-"+id), label, btnOpt{small: true}).Clicked() {
			if open {
				a.closeTrafficSetup(id)
			} else {
				a.openTrafficSetup(id)
			}
		}
	})
	if open {
		a.trafficSetupRows(c, d, last)
	}
}

// trafficSetupRows are the open setup: where the proxy listens, the
// certificate, the steps on the phone and, on Android, the cable route.
func (a *app) trafficSetupRows(c *mg.Context, d gateway.DeviceView, last bool) {
	p := pal(c)
	id := d.Info.ID
	st, have := a.trafficSetupOf(c, id)
	android := d.Info.Platform == driver.Android
	for _, addr := range st.Proxies {
		a.copyRow(c, locales.TrafficProxyAddress(), addr, addr, locales.TrafficCopyProxy(), locales.TrafficCopiedProxy(), false)
	}
	if st.CertURL != "" {
		a.copyRow(c, locales.TrafficCertificate(), st.CertURL, st.CertURL, locales.TrafficCopyCertURL(), locales.TrafficCopiedCertURL(), false)
	}
	groupRow(c, mg.Column(c).Gap(sp2), last && !(android && st.CanRoute)).Children(func() {
		switch {
		case !have:
			mg.Text(c, locales.TrafficSetupReading()).FontSize(fsSmall).TextColor(p.ink2)
		case st.Problem != "":
			mg.Text(c, trafficProblem(st.Problem, d.Info.Name)).FontSize(fsSmall).LineHeight(1.4).TextColor(p.ink2)
		case len(st.Proxies) == 0 && !st.Routed:
			mg.Text(c, locales.TrafficSetupWaiting()).FontSize(fsSmall).TextColor(p.ink2)
		}
		if st.CAName != "" {
			mg.Text(c, locales.TrafficCAInfo(st.CAName, st.Fingerprint)).FontSize(fsSmall).LineHeight(1.4).TextColor(p.ink2).Selectable()
		}
		steps := locales.TrafficStepsIOS()
		if android {
			steps = locales.TrafficStepsAndroid()
		}
		mg.Text(c, steps).FontSize(fsSmall).LineHeight(1.5)
		if android {
			mg.Text(c, locales.TrafficAndroidAppsWarning()).FontSize(fsSmall).LineHeight(1.4).TextColor(p.ink2)
		}
		mg.Text(c, locales.TrafficOutsideTasks()).FontSize(fsSmall).LineHeight(1.4).TextColor(p.ink2)
	})
	if android && st.CanRoute {
		route := st.Route
		if a.toggleRowFor(c, "traffic-route-"+id, locales.TrafficRouteTitle(), locales.TrafficRouteDesc(strconv.Itoa(trafficPortOf(st))), last, &route) {
			a.setTrafficRoute(d, route)
		}
	}
}

// trafficPortOf is the port the proxy listens at, from its addresses.
func trafficPortOf(st gateway.TrafficSetup) int {
	for _, addr := range st.Proxies {
		if _, port, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(port); err == nil {
				return n
			}
		}
	}
	return gateway.TrafficPort
}

// trafficProblem says a TrafficSetup.Problem in the person's words.
func trafficProblem(problem, phone string) string {
	switch problem {
	case gateway.TrafficListenFailed:
		return locales.TrafficProblemListenFailed()
	case gateway.TrafficNoCA:
		return locales.TrafficProblemNoCA()
	case gateway.TrafficRouteFailed:
		return locales.TrafficProblemRouteFailed(phone)
	case gateway.TrafficRouteBusy:
		return locales.TrafficProblemRouteBusy(phone)
	}
	return locales.TrafficProblemNoAddress(phone)
}
