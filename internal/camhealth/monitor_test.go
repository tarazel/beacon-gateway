package camhealth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// newTestMonitor builds a monitor with a controllable clock and a fetcher whose
// return values are swapped between polls via the returned setter.
func newTestMonitor(cams []string, offlineAfter time.Duration) (*Monitor, func(map[string]float64, error), func(time.Duration)) {
	var (
		curFPS map[string]float64
		curErr error
	)
	fetch := func(context.Context) (map[string]float64, error) { return curFPS, curErr }
	m := New(fetch, cams, time.Second, offlineAfter, slog.New(slog.NewTextHandler(io.Discard, nil)))

	now := time.Unix(1_700_000_000, 0)
	m.clock = func() time.Time { return now }

	setFetch := func(f map[string]float64, e error) { curFPS, curErr = f, e }
	advance := func(d time.Duration) { now = now.Add(d) }
	return m, setFetch, advance
}

func TestMonitor_OnlineWhileFramesFlow(t *testing.T) {
	m, set, advance := newTestMonitor([]string{"deimos"}, 120*time.Second)
	set(map[string]float64{"deimos": 5.0}, nil)

	m.poll(context.Background())
	if m.Offline("deimos") {
		t.Fatal("camera with live frames should be online")
	}
	advance(10 * time.Minute)
	m.poll(context.Background())
	if m.Offline("deimos") {
		t.Fatal("camera still delivering frames should stay online")
	}
}

func TestMonitor_FlipsOfflineOnlyAfterDebounce(t *testing.T) {
	m, set, advance := newTestMonitor([]string{"deimos"}, 120*time.Second)

	// Healthy baseline.
	set(map[string]float64{"deimos": 5.0}, nil)
	m.poll(context.Background())

	// Frames stop. A brief outage (under the 120s window) must NOT flag offline.
	set(map[string]float64{"deimos": 0.0}, nil)
	advance(60 * time.Second)
	m.poll(context.Background())
	if m.Offline("deimos") {
		t.Fatal("60s of no frames is within debounce — should not be offline yet")
	}

	// Sustained past the window -> offline.
	advance(70 * time.Second) // 130s total since last good frame
	m.poll(context.Background())
	if !m.Offline("deimos") {
		t.Fatal("camera down longer than offlineAfter should be flagged offline")
	}
}

func TestMonitor_RecoversImmediately(t *testing.T) {
	m, set, advance := newTestMonitor([]string{"deimos"}, 120*time.Second)
	set(map[string]float64{"deimos": 5.0}, nil)
	m.poll(context.Background())

	set(map[string]float64{"deimos": 0.0}, nil)
	advance(200 * time.Second)
	m.poll(context.Background())
	if !m.Offline("deimos") {
		t.Fatal("precondition: camera should be offline")
	}

	// One good sample clears it, no debounce on the way back up.
	set(map[string]float64{"deimos": 4.5}, nil)
	m.poll(context.Background())
	if m.Offline("deimos") {
		t.Fatal("camera should recover to online on the first good frame")
	}
}

func TestMonitor_FetchErrorCountsAsDown(t *testing.T) {
	m, set, advance := newTestMonitor([]string{"deimos"}, 120*time.Second)
	set(map[string]float64{"deimos": 5.0}, nil)
	m.poll(context.Background())

	// Frigate unreachable: repeated errors past the window flag the camera.
	set(nil, errors.New("connection refused"))
	advance(200 * time.Second)
	m.poll(context.Background())
	if !m.Offline("deimos") {
		t.Fatal("sustained stats-fetch failure should flag the camera offline")
	}
}

func TestMonitor_GracePeriodAtStartup(t *testing.T) {
	// A camera that's already down when the gateway starts must not be flagged
	// on the very first poll — it gets the full offlineAfter grace period.
	m, set, _ := newTestMonitor([]string{"deimos"}, 120*time.Second)
	set(map[string]float64{"deimos": 0.0}, nil)
	m.poll(context.Background())
	if m.Offline("deimos") {
		t.Fatal("camera down at startup should get a grace period, not flag immediately")
	}
}

func TestMonitor_UnknownCameraNeverOffline(t *testing.T) {
	m, set, advance := newTestMonitor([]string{"deimos"}, 120*time.Second)
	set(map[string]float64{"deimos": 0.0}, nil)
	advance(500 * time.Second)
	m.poll(context.Background())
	if m.Offline("doorbell") {
		t.Fatal("a camera the monitor doesn't track should report online (no tag)")
	}
}
