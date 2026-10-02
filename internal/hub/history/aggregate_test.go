package history

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestSampleRow(t *testing.T) {
	nan, inf := math.NaN(), math.Inf(1)
	tempHot, tempBogus, tempNaN := 71.5, 900.0, nan

	tests := []struct {
		name   string
		mod    func(*protocol.Metrics)
		ok     bool
		assert func(*testing.T, store.MetricRow)
	}{
		{"plain", func(*protocol.Metrics) {}, true, func(t *testing.T, r store.MetricRow) {
			if r.Samples != 1 || r.CPUAvg != 50 || r.CPUMax != 50 || r.TempAvg == nil || *r.TempAvg != 45 ||
				r.MemUsedAvg != float64(2<<30) || r.MemTotal != 8<<30 || r.NetRxAvg != 5000 || len(r.Disks) != 2 {
				t.Errorf("%+v", r)
			}
		}},
		{"cpu NaN drops the sample", func(m *protocol.Metrics) { m.CPUPercent = nan }, false, nil},
		{"cpu Inf drops the sample", func(m *protocol.Metrics) { m.CPUPercent = inf }, false, nil},
		{"cpu clamped", func(m *protocol.Metrics) { m.CPUPercent = 250 }, true, func(t *testing.T, r store.MetricRow) {
			if r.CPUAvg != 100 {
				t.Errorf("cpu %v", r.CPUAvg)
			}
		}},
		{"negative cpu", func(m *protocol.Metrics) { m.CPUPercent = -3 }, true, func(t *testing.T, r store.MetricRow) {
			if r.CPUAvg != 0 {
				t.Errorf("cpu %v", r.CPUAvg)
			}
		}},
		{"no sensor", func(m *protocol.Metrics) { m.TempC = nil }, true, func(t *testing.T, r store.MetricRow) {
			if r.TempAvg != nil || r.TempMax != nil {
				t.Error("temp must stay nil, not 0")
			}
		}},
		{"hot sensor", func(m *protocol.Metrics) { m.TempC = &tempHot }, true, func(t *testing.T, r store.MetricRow) {
			if *r.TempAvg != 71.5 {
				t.Error("temp")
			}
		}},
		{"implausible temperature", func(m *protocol.Metrics) { m.TempC = &tempBogus }, true, func(t *testing.T, r store.MetricRow) {
			if r.TempAvg != nil {
				t.Error("temp must be dropped")
			}
		}},
		{"NaN temperature", func(m *protocol.Metrics) { m.TempC = &tempNaN }, true, func(t *testing.T, r store.MetricRow) {
			if r.TempAvg != nil {
				t.Error("temp must be dropped")
			}
		}},
		{"bad net rates", func(m *protocol.Metrics) { m.Net.RxBytesPerSec, m.Net.TxBytesPerSec = nan, -5 }, true, func(t *testing.T, r store.MetricRow) {
			if r.NetRxAvg != 0 || r.NetTxAvg != 0 {
				t.Errorf("%v %v", r.NetRxAvg, r.NetTxAvg)
			}
		}},
		{"disk used capped to total, duplicates and bad mounts skipped", func(m *protocol.Metrics) {
			m.Disks = []protocol.Disk{{Mount: "/", Total: 100, Used: 400}, {Mount: "/", Total: 5, Used: 5}, {Mount: "", Total: 1}, {Mount: strings.Repeat("x", 300), Total: 1}}
		}, true, func(t *testing.T, r store.MetricRow) {
			if len(r.Disks) != 1 || r.Disks[0].Used != 100 {
				t.Errorf("%+v", r.Disks)
			}
		}},
		{"too many mounts", func(m *protocol.Metrics) {
			m.Disks = nil
			for i := 0; i < 100; i++ {
				m.Disks = append(m.Disks, protocol.Disk{Mount: "/m" + strings.Repeat("x", i), Total: 1})
			}
		}, true, func(t *testing.T, r store.MetricRow) {
			if len(r.Disks) != maxMounts {
				t.Errorf("%d mounts", len(r.Disks))
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := sample(t0, 50)
			tc.mod(&m)
			r, ok := sampleRow(hostA, m)
			if ok != tc.ok {
				t.Fatalf("ok=%v", ok)
			}
			if ok {
				tc.assert(t, r)
			}
		})
	}
}

func TestCombineWeighted(t *testing.T) {
	temp := func(v float64) *float64 { return &v }
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	rows := []store.MetricRow{
		{Samples: 30, CPUAvg: 10, CPUMax: 40, MemUsedAvg: 100, MemUsedMax: 120, MemTotal: 1000, TempAvg: temp(50), TempMax: temp(55),
			NetRxAvg: 10, NetRxMax: 20, NetTxAvg: 1, NetTxMax: 2, Disks: []store.DiskUsage{{Mount: "/", Used: 10, Total: 100}}},
		// a minute without sensor, a new disk appears, memory total changes
		{Samples: 10, CPUAvg: 50, CPUMax: 60, MemUsedAvg: 300, MemUsedMax: 310, MemTotal: 2000,
			NetRxAvg: 30, NetRxMax: 25, NetTxAvg: 3, NetTxMax: 4, Disks: []store.DiskUsage{{Mount: "/", Used: 30, Total: 200}, {Mount: "/usb", Used: 7, Total: 9}}},
		{Samples: 20, CPUAvg: 20, CPUMax: 30, MemUsedAvg: 200, MemUsedMax: 210, MemTotal: 2000, TempAvg: temp(60), TempMax: temp(70),
			NetRxAvg: 0, NetRxMax: 0, NetTxAvg: 0, NetTxMax: 0},
	}
	got, ok := Combine(hostA, at, rows)
	if !ok {
		t.Fatal("no row")
	}
	near := func(name string, got, want float64) {
		t.Helper()
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	near("samples", float64(got.Samples), 60)
	near("cpu avg", got.CPUAvg, (10*30+50*10+20*20)/60.0)
	near("cpu max", got.CPUMax, 60)
	near("mem avg", got.MemUsedAvg, (100*30+300*10+200*20)/60.0)
	near("mem max", got.MemUsedMax, 310)
	near("mem total", float64(got.MemTotal), 2000)
	near("temp avg", *got.TempAvg, (50*30+60*20)/50.0) // weighted over the samples that had a sensor
	near("temp max", *got.TempMax, 70)
	near("rx avg", got.NetRxAvg, (10*30+30*10)/60.0)
	near("rx max", got.NetRxMax, 25)
	if len(got.Disks) != 2 || got.Disks[0].Mount != "/" || got.Disks[1].Mount != "/usb" {
		t.Fatalf("disks %+v", got.Disks)
	}
	near("disk / used", float64(got.Disks[0].Used), (10*30+30*10)/40.0) // rows 1 and 2 only
	near("disk / total", float64(got.Disks[0].Total), 200)
	near("disk /usb used", float64(got.Disks[1].Used), 7)

	if _, ok := Combine(hostA, at, nil); ok {
		t.Error("no rows must give no bucket")
	}
}
