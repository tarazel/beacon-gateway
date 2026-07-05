// Package camhealth tracks per-camera online/offline state by polling Frigate's
// stats. A camera is flagged offline once it has reported no live frames — or
// Frigate has been unreachable — for longer than a debounce window. The gateway
// exposes this on the camera API so clients can show an "offline" tag; it does
// NOT push a notification (a flapping camera would spam it).
package camhealth

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StatsFetcher returns each camera's current source frame rate (camera_fps),
// keyed by Frigate camera id. Satisfied by (*frigate.Client).CameraFPS.
type StatsFetcher func(ctx context.Context) (map[string]float64, error)

// Monitor polls camera liveness and reports offline state with an asymmetric
// debounce: a camera must be down for offlineAfter before it flips to offline
// (so a brief ffmpeg restart doesn't toggle the tag), but recovers to online on
// the first good sample. Zero value is not usable — use New.
type Monitor struct {
	fetch        StatsFetcher
	cameras      []string
	interval     time.Duration
	offlineAfter time.Duration
	log          *slog.Logger
	// clock is time.Now in production; overridable in tests.
	clock func() time.Time

	mu         sync.RWMutex
	lastSeenUp map[string]time.Time // camera id -> last poll it had live frames
	offline    map[string]bool
}

// New builds a Monitor for the given camera ids. interval is the poll period;
// offlineAfter is how long a camera must have no frames before it's flagged
// offline. A sensible pairing is 30s / 120s (matching Frigate's own 120s
// no-segments watchdog).
func New(fetch StatsFetcher, cameraIDs []string, interval, offlineAfter time.Duration, log *slog.Logger) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	return &Monitor{
		fetch:        fetch,
		cameras:      append([]string(nil), cameraIDs...),
		interval:     interval,
		offlineAfter: offlineAfter,
		log:          log,
		clock:        time.Now,
		lastSeenUp:   make(map[string]time.Time, len(cameraIDs)),
		offline:      make(map[string]bool, len(cameraIDs)),
	}
}

// Offline reports whether camera id is currently flagged offline. Unknown
// cameras (not monitored) report false, so a missing/unconfigured camera never
// shows a spurious tag.
func (m *Monitor) Offline(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.offline[id]
}

// Run polls until ctx is cancelled. Intended to run in its own goroutine. It is
// a no-op (returns immediately) when there's no fetcher or no cameras.
func (m *Monitor) Run(ctx context.Context) {
	if m.fetch == nil || len(m.cameras) == 0 {
		return
	}
	m.poll(ctx) // prompt first sample so state is fresh soon after startup
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.poll(ctx)
		}
	}
}

func (m *Monitor) poll(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	fps, err := m.fetch(reqCtx)
	cancel()
	if err != nil {
		// Frigate unreachable: treat as "no live frames for any camera" this
		// tick. We don't refresh lastSeenUp, so the offlineAfter window still
		// governs when cameras flip — a single failed poll won't flag them.
		m.log.Debug("camera health: stats fetch failed", "err", err)
		fps = nil
	}

	now := m.clock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.cameras {
		last, seen := m.lastSeenUp[id]
		if !seen {
			// First observation: baseline to now so a camera that's down at
			// startup gets the full grace period before being flagged.
			last = now
			m.lastSeenUp[id] = now
		}
		if v, ok := fps[id]; ok && v > 0 {
			m.lastSeenUp[id] = now
			last = now
		}
		down := now.Sub(last) >= m.offlineAfter
		if down != m.offline[id] {
			m.offline[id] = down
			if down {
				m.log.Warn("camera offline", "camera", id)
			} else {
				m.log.Info("camera back online", "camera", id)
			}
		}
	}
}
