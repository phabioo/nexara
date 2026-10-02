package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/views"
)

// historyChartsTarget is the id of the element that refreshes itself; a request that targets it gets the
// fragment instead of the whole page.
const historyChartsTarget = "hist-charts"

// historyViewStep is the bucket width the view asks for. It equals history.Ranges except for 30 days, which is
// read from hours at two hours per point: 361 instead of 721 points keep the paths (and the page) small and are
// still more points than a chart is pixels wide.
var historyViewStep = map[string]time.Duration{
	"24h": 5 * time.Minute,
	"7d":  30 * time.Minute,
	"30d": 2 * time.Hour,
}

// historyDiskStep is the bucket width of the disk charts. Disk usage moves slowly, and a step below an hour is
// answered from the minute rows, whose JSON disk column has to be decoded row by row (10 080 rows for a week):
// the week is read from hours instead, which is 60 times cheaper and looks the same.
var historyDiskStep = map[string]time.Duration{
	"24h": 5 * time.Minute,
	"7d":  time.Hour,
	"30d": 2 * time.Hour,
}

// historyPoll is how often the charts reload themselves. A closed minute reaches the database once a minute, so
// a 24 h chart has something new every minute; the longer ranges move slowly. A fragment poll was chosen over
// the SSE stream: the history service only writes minutes after they closed, so there is no event to push, and
// the hub would have to merge a live sample into a bucket it does not know the shape of.
var historyPoll = map[string]time.Duration{
	"24h": time.Minute,
	"7d":  5 * time.Minute,
	"30d": 5 * time.Minute,
}

// routesHistory registers the History view: GET /history shows the default host, GET /hosts/{host}/history a
// specific one. The range is the ?range= parameter (24h, 7d, 30d; anything else means 24h).
func (s *Server) routesHistory(mux *http.ServeMux) {
	mux.HandleFunc("GET /history", s.handleHistoryDefault)
	mux.HandleFunc("GET /hosts/{host}/history", s.handleHistoryHost)
}

func (s *Server) handleHistoryDefault(w http.ResponseWriter, r *http.Request) {
	h, ok := s.defaultHost()
	if !ok {
		s.renderHistory(w, r, nil)
		return
	}
	s.renderHistory(w, r, &h)
}

func (s *Server) handleHistoryHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	s.renderHistory(w, r, &h)
}

// historyRange resolves the ?range= parameter; an unknown value is the default, the first range.
func historyRange(r *http.Request) history.Range {
	if rng, ok := history.ParseRange(r.URL.Query().Get("range")); ok {
		return rng
	}
	return history.Ranges[0]
}

func (s *Server) renderHistory(w http.ResponseWriter, r *http.Request, h *grid.HostInfo) {
	if s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	rng := historyRange(r)
	page := views.HistoryPage{Layout: s.layout(r, "history", h), RangeKey: rng.Key}
	page.Title = "History"
	if h == nil {
		page.State = views.HistoryNoHosts
	} else {
		page.Host, page.Label = h.Name, hostLabel(*h)
		base := hostURL(h.Name) + "/history"
		page.Ranges = views.NewHistoryRanges(base, rng.Key)
		charts, loc, err := s.historyCharts(r.Context(), *h, rng)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		page.Charts = charts
		page.Charts.PollURL = base
		if rng.Key != history.Ranges[0].Key {
			page.Charts.PollURL += "?range=" + rng.Key
		}
		page.Charts.PollEvery = strconv.Itoa(int(historyPoll[rng.Key]/time.Second)) + "s"
		page.Zone = zoneName(loc, s.now())
	}

	var err error
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == historyChartsTarget {
		err = s.renderer.RenderPartial(w, "history-charts", page.Charts)
	} else {
		err = s.renderer.Render(w, "history", page)
	}
	if err != nil {
		s.serverError(w, r, err)
	}
}

// zoneName names the time zone of the axis: the IANA name, or the abbreviation when the hub runs on the
// machine's local zone.
func zoneName(loc *time.Location, now time.Time) string {
	if loc == nil {
		return "UTC"
	}
	if name := loc.String(); name != "Local" && name != "" {
		return name
	}
	abbr, _ := now.In(loc).Zone()
	return abbr
}

// historyCharts reads each series of the host once (six queries: cpu, memory, temperature, rx, tx and all
// mounts together) on one common time grid and builds the cards.
func (s *Server) historyCharts(ctx context.Context, h grid.HostInfo, rng history.Range) (views.HistoryCharts, *time.Location, error) {
	svc := s.svc.History
	if svc == nil {
		return views.HistoryCharts{State: views.HistoryUnavailable, Message: "History is not available on this hub."}, time.UTC, nil
	}
	in := views.HistoryInput{
		Label:    hostLabel(h),
		Online:   h.Online,
		LastSeen: views.AgoText(s.now(), h.LastSeen),
		Range:    rng,
		Loc:      svc.Location(),
	}
	to := svc.Now()
	from := to.Add(-rng.Span)
	step := historyViewStep[rng.Key]
	host := string(h.ID)

	for _, q := range []struct {
		metric history.Metric
		dst    *history.Series
	}{
		{history.MetricCPU, &in.CPU}, {history.MetricMem, &in.Mem}, {history.MetricTemp, &in.Temp},
		{history.MetricNetRx, &in.Rx}, {history.MetricNetTx, &in.Tx},
	} {
		ser, err := svc.Series(ctx, host, q.metric, from, to, step)
		if err != nil {
			return views.HistoryCharts{}, nil, historyError(q.metric, err)
		}
		*q.dst = ser
	}
	disks, err := svc.DiskSeries(ctx, host, from, to, historyDiskStep[rng.Key])
	if err != nil {
		return views.HistoryCharts{}, nil, historyError("disks", err)
	}
	in.Disks = disks
	return views.NewHistoryCharts(in), in.Loc, nil
}

func historyError(what history.Metric, err error) error {
	return fmt.Errorf("history %s: %w", what, err)
}
