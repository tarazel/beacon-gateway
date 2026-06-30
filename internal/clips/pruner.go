// Package clips owns the lifecycle of the on-disk clip cache: a background
// pruner that deletes cached clips for events older than the configured
// retention window, unless the event has been pinned.
package clips

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultInterval = 6 * time.Hour

// RetentionFunc returns the configured retention window in days. A value <= 0
// disables automatic pruning.
type RetentionFunc func(ctx context.Context) (int, error)

// MetaFunc reports, for a cached clip's event id, whether the clip is pinned,
// the event's start time, and whether the event row was found.
type MetaFunc func(ctx context.Context, id string) (keep bool, start time.Time, found bool, err error)

type Pruner struct {
	dir       string
	retention RetentionFunc
	meta      MetaFunc
	log       *slog.Logger
	interval  time.Duration
	now       func() time.Time
}

func NewPruner(dir string, log *slog.Logger, retention RetentionFunc, meta MetaFunc) *Pruner {
	return &Pruner{
		dir:       dir,
		retention: retention,
		meta:      meta,
		log:       log,
		interval:  defaultInterval,
		now:       time.Now,
	}
}

// Run prunes once immediately, then on a fixed interval until ctx is cancelled.
func (p *Pruner) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		if removed, err := p.PruneOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("clip prune failed", "err", err)
		} else if removed > 0 {
			p.log.Info("clip prune", "removed", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PruneOnce removes every cached *.mp4 whose event is older than the retention
// window and not pinned. Files whose event row is missing are aged by file
// modification time instead. Returns the number of files removed.
func (p *Pruner) PruneOnce(ctx context.Context) (int, error) {
	days, err := p.retention(ctx)
	if err != nil {
		return 0, err
	}
	if days <= 0 {
		return 0, nil // pruning disabled
	}

	entries, err := os.ReadDir(p.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	cutoff := p.now().Add(-time.Duration(days) * 24 * time.Hour)
	removed := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".mp4") {
			continue
		}
		id := strings.TrimSuffix(name, ".mp4")

		keep, start, found, err := p.meta(ctx, id)
		if err != nil {
			p.log.Warn("clip prune lookup failed", "id", id, "err", err)
			continue
		}
		if keep {
			continue
		}

		basis := start
		if !found {
			info, err := e.Info()
			if err != nil {
				continue
			}
			basis = info.ModTime()
		}
		if !basis.Before(cutoff) {
			continue
		}

		path := filepath.Join(p.dir, name)
		if err := os.Remove(path); err != nil {
			p.log.Warn("clip prune remove failed", "path", path, "err", err)
			continue
		}
		removed++
	}
	return removed, nil
}
