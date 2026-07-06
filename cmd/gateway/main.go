package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tarazel/beacon-gateway/internal/api"
	"github.com/tarazel/beacon-gateway/internal/apns"
	"github.com/tarazel/beacon-gateway/internal/auth"
	"github.com/tarazel/beacon-gateway/internal/camhealth"
	"github.com/tarazel/beacon-gateway/internal/cameras"
	"github.com/tarazel/beacon-gateway/internal/clips"
	"github.com/tarazel/beacon-gateway/internal/config"
	"github.com/tarazel/beacon-gateway/internal/db"
	"github.com/tarazel/beacon-gateway/internal/events"
	"github.com/tarazel/beacon-gateway/internal/frigate"
	"github.com/tarazel/beacon-gateway/internal/go2rtc"
	"github.com/tarazel/beacon-gateway/internal/mqtt"
	"github.com/tarazel/beacon-gateway/internal/notifrules"
	"github.com/tarazel/beacon-gateway/internal/settings"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	database, err := db.Open(rootCtx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer database.Close()

	userStore := auth.NewStore(database)
	jwtIssuer := auth.NewJWTIssuer(cfg.Auth.JWTSigningKey, cfg.Auth.AccessTokenTTL)
	appleVerifier := auth.NewAppleVerifier(
		append([]string{cfg.Auth.AppleClientID}, cfg.Auth.AppleAllowedAudiences...)...,
	)
	googleVerifier := auth.NewGoogleVerifier(
		append([]string{cfg.Auth.GoogleClientID}, cfg.Auth.GoogleAllowedAudiences...)...,
	)
	eventStore := events.NewStore(database)
	settingsStore := settings.NewStore(database)
	rulesStore := notifrules.NewStore(database)
	frigateClient := frigate.NewClient(cfg.Frigate)
	cameraRegistry := cameras.NewRegistry(cfg.Cameras)
	go2rtcClient := go2rtc.NewClient(cfg.Go2RTC.BaseURL)

	// Poll Frigate for per-camera liveness so the API can surface an "offline"
	// tag. Push is intentionally not wired to this — a flapping camera would spam.
	camIDs := make([]string, 0, len(cfg.Cameras))
	for _, c := range cameraRegistry.List() {
		camIDs = append(camIDs, c.ID)
	}
	cameraHealth := camhealth.New(frigateClient.CameraFPS, camIDs, cfg.CameraHealth.PollInterval, cfg.CameraHealth.OfflineAfter, log)
	go cameraHealth.Run(rootCtx)

	pushTransport, err := buildPushTransport(rootCtx, cfg, settingsStore, log)
	if err != nil {
		return err
	}
	apnsSender := apns.NewSender(pushTransport, database, ruleAdapter{rulesStore}, cfg.APNs.UseSandbox, log)

	// Constructed here (before handlers) so the health endpoint can report the
	// live broker connection; Start()/Stop() are wired below.
	mqttSub := mqtt.New(cfg.MQTT, log, eventDispatcher(log, eventStore, apnsSender, frigateClient, cfg))

	handlers := api.NewHandlers(cfg, log, database, userStore, jwtIssuer, appleVerifier, googleVerifier, eventStore, frigateClient, cameraRegistry, go2rtcClient, settingsStore, rulesStore, cameraHealth, mqttSub)
	router := api.NewRouter(handlers, jwtIssuer, userStore, log)

	clipPruner := clips.NewPruner(cfg.ClipsDir(), log,
		func(ctx context.Context) (int, error) {
			return settingsStore.GetInt(ctx, settings.KeyClipRetentionDays, settings.DefaultClipRetentionDays)
		},
		func(ctx context.Context, id string) (bool, time.Time, bool, error) {
			ev, err := eventStore.Get(ctx, id)
			if err != nil || ev == nil {
				return false, time.Time{}, false, err
			}
			return ev.KeepClip, ev.StartTime, true, nil
		},
	)
	go clipPruner.Run(rootCtx)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	go func() {
		if err := mqttSub.Start(rootCtx); err != nil {
			log.Warn("mqtt failed to start; will keep retrying in background", "err", err)
		}
	}()
	defer mqttSub.Stop()

	select {
	case <-rootCtx.Done():
		log.Info("shutdown signal received")
	case err := <-serverErr:
		log.Error("http server error", "err", err)
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Warn("http shutdown error", "err", err)
	}
	return nil
}

// buildPushTransport chooses how the gateway delivers pushes: via the central
// relay when RELAY_URL is set (the hosted/paid path), else directly to APNs with
// the gateway's own .p8 (self-hosted), else nil (push disabled).
func buildPushTransport(_ context.Context, cfg *config.Config, settingsStore *settings.Store, log *slog.Logger) (apns.Transport, error) {
	if cfg.Relay.URL != "" {
		// The instance token is obtained lazily: the gateway registers with the relay
		// on the owner's first sign-in (see api.Handlers), not at startup — there is
		// no provider ID token to present until someone signs in. Read the token fresh
		// from settings on each delivery so a mid-run registration is picked up without
		// a restart; "" means not yet registered (Sender skips those pushes).
		tokenFn := func(ctx context.Context) (string, error) {
			return settingsStore.GetString(ctx, settings.KeyRelayInstanceToken, "")
		}
		log.Info("push transport: relay", "url", cfg.Relay.URL)
		return apns.NewRelayTransport(cfg.Relay.URL, tokenFn, nil), nil
	}
	if cfg.APNsConfigured() {
		dt, err := apns.NewDirectTransport(cfg.APNs)
		if err != nil {
			return nil, err
		}
		log.Info("push transport: direct APNs")
		return dt, nil
	}
	return nil, nil
}

// prewarmClip caches (downloads + remuxes) an event's clip ahead of any user
// request. Runs in its own goroutine with a fresh, bounded context — the MQTT
// message context is short-lived, but a remux can take a while. Best-effort:
// failures are logged, not surfaced (the clip still remuxes on demand later).
func prewarmClip(log *slog.Logger, frig *frigate.Client, cfg *config.Config, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := frig.EnsureCachedClip(ctx, id, cfg.ClipsDir()); err != nil {
		log.Warn("clip prewarm failed", "event_id", id, "err", err)
		return
	}
	log.Info("clip prewarmed", "event_id", id)
}

// ruleAdapter bridges the notifrules.Store to the apns.Ruler interface, keeping
// the apns package unaware of the concrete rules implementation (and vice versa).
type ruleAdapter struct{ store *notifrules.Store }

func (a ruleAdapter) Allows(ctx context.Context, userID string, ev apns.RuleEvent) bool {
	return a.store.Allows(ctx, userID, notifrules.Event{
		Camera: ev.Camera,
		Label:  ev.Label,
		Zones:  ev.Zones,
		Score:  ev.Score,
	})
}

func eventDispatcher(log *slog.Logger, store *events.Store, sender *apns.Sender, frig *frigate.Client, cfg *config.Config) mqtt.MessageHandler {
	return func(ctx context.Context, topic string, payload []byte) {
		ev, err := frigate.ParseEvent(payload)
		if err != nil {
			log.Warn("event parse failed", "topic", topic, "err", err)
			return
		}

		created, err := store.Upsert(ctx, ev, payload)
		if err != nil {
			log.Error("event upsert failed", "id", ev.After.ID, "err", err)
			return
		}

		// On the end phase the clip is available in Frigate. Pre-warm the cache in
		// the background so the notification-tap → clip path skips the synchronous
		// download+remux (which can exceed Cloudflare's timeout for long clips).
		if ev.Type == frigate.PhaseEnd && ev.After.HasClip && frig != nil {
			go prewarmClip(log, frig, cfg, ev.After.ID)
		}

		if !created {
			return
		}

		state := ev.After
		title := events.PushTitle(state.Camera)
		body := events.PushBody(state.Label, state.SubLabel)
		snapshotURL := ""
		if state.HasSnapshot {
			snapshotURL = cfg.PublicSnapshotURL(state.ID)
		}

		if err := sender.SendToAll(ctx, apns.Notification{
			Title:       title,
			Body:        body,
			ThreadID:    state.Camera,
			EventID:     state.ID,
			Camera:      state.Camera,
			Label:       state.Label,
			SnapshotURL: snapshotURL,
			Zones:       state.Zones,
			Score:       state.TopScore,
		}); err != nil && !errors.Is(err, apns.ErrSubscriptionInactive) {
			// Subscription-inactive is already logged loudly inside SendToAll; don't
			// double-warn. Everything else is an unexpected delivery failure.
			log.Warn("push send failed", "event_id", state.ID, "err", err)
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
