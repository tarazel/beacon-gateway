package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hydak/beacon-gateway/internal/api"
	"github.com/hydak/beacon-gateway/internal/apns"
	"github.com/hydak/beacon-gateway/internal/auth"
	"github.com/hydak/beacon-gateway/internal/cameras"
	"github.com/hydak/beacon-gateway/internal/clips"
	"github.com/hydak/beacon-gateway/internal/config"
	"github.com/hydak/beacon-gateway/internal/db"
	"github.com/hydak/beacon-gateway/internal/events"
	"github.com/hydak/beacon-gateway/internal/frigate"
	"github.com/hydak/beacon-gateway/internal/go2rtc"
	"github.com/hydak/beacon-gateway/internal/mqtt"
	"github.com/hydak/beacon-gateway/internal/settings"
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
	appleVerifier := auth.NewAppleVerifier(cfg.Auth.AppleClientID)
	eventStore := events.NewStore(database)
	settingsStore := settings.NewStore(database)
	frigateClient := frigate.NewClient(cfg.Frigate)
	cameraRegistry := cameras.NewRegistry(cfg.Cameras)
	go2rtcClient := go2rtc.NewClient(cfg.Go2RTC.BaseURL)

	pushTransport, err := buildPushTransport(rootCtx, cfg, settingsStore, log)
	if err != nil {
		return err
	}
	apnsSender := apns.NewSender(pushTransport, database, cfg.APNs.UseSandbox, log)

	handlers := api.NewHandlers(cfg, log, database, userStore, jwtIssuer, appleVerifier, eventStore, frigateClient, cameraRegistry, go2rtcClient, settingsStore)
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

	mqttSub := mqtt.New(cfg.MQTT, log, eventDispatcher(log, eventStore, apnsSender, cfg))
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
func buildPushTransport(ctx context.Context, cfg *config.Config, settingsStore *settings.Store, log *slog.Logger) (apns.Transport, error) {
	if cfg.Relay.URL != "" {
		token, err := ensureRelayRegistration(ctx, cfg, settingsStore, log)
		if err != nil {
			return nil, err
		}
		log.Info("push transport: relay", "url", cfg.Relay.URL)
		return apns.NewRelayTransport(cfg.Relay.URL, token, nil), nil
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

// ensureRelayRegistration returns the stored relay instance token, registering
// with the relay on first boot (using RELAY_REGISTRATION_SECRET) if none exists.
func ensureRelayRegistration(ctx context.Context, cfg *config.Config, settingsStore *settings.Store, log *slog.Logger) (string, error) {
	tok, err := settingsStore.GetString(ctx, settings.KeyRelayInstanceToken, "")
	if err != nil {
		return "", err
	}
	if tok != "" {
		return tok, nil
	}
	if cfg.Relay.RegistrationSecret == "" {
		return "", fmt.Errorf("relay configured (RELAY_URL) but no stored instance token and RELAY_REGISTRATION_SECRET is unset")
	}
	resp, err := apns.RegisterWithRelay(ctx, cfg.Relay.URL, cfg.Relay.RegistrationSecret, nil)
	if err != nil {
		return "", fmt.Errorf("relay registration: %w", err)
	}
	if err := settingsStore.SetString(ctx, settings.KeyRelayInstanceToken, resp.InstanceToken); err != nil {
		return "", fmt.Errorf("store relay instance token: %w", err)
	}
	log.Info("registered with relay", "instance_id", resp.InstanceID, "plan", resp.Plan)
	return resp.InstanceToken, nil
}

func eventDispatcher(log *slog.Logger, store *events.Store, sender *apns.Sender, cfg *config.Config) mqtt.MessageHandler {
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

		if !created {
			return
		}

		state := ev.After
		title := titleFor(state.Camera)
		body := bodyFor(state.Label, state.SubLabel)
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
		}); err != nil {
			log.Warn("push send failed", "event_id", state.ID, "err", err)
		}
	}
}

func titleFor(camera string) string {
	if camera == "" {
		return "Activity detected"
	}
	return camera
}

func bodyFor(label string, sub *string) string {
	if sub != nil && *sub != "" {
		return *sub + " detected"
	}
	if label == "" {
		return "Motion detected"
	}
	return label + " detected"
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
