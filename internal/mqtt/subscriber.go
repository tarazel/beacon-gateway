package mqtt

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	mqttlib "github.com/eclipse/paho.mqtt.golang"

	"github.com/tarazel/beacon-gateway/internal/config"
)

type MessageHandler func(ctx context.Context, topic string, payload []byte)

type Subscriber struct {
	cfg    config.MQTT
	client mqttlib.Client
	log    *slog.Logger
	onMsg  MessageHandler
	// connected mirrors the broker connection, flipped by paho's connect/lost
	// callbacks. Read via Connected() from the health endpoint's HTTP goroutine,
	// so it's atomic rather than a racy read of the client field.
	connected atomic.Bool
}

// Connected reports whether the MQTT client currently has a live broker
// connection. Nil-safe via the zero value (false) before Start runs.
func (s *Subscriber) Connected() bool { return s.connected.Load() }

func New(cfg config.MQTT, log *slog.Logger, onMsg MessageHandler) *Subscriber {
	return &Subscriber{cfg: cfg, log: log, onMsg: onMsg}
}

func (s *Subscriber) Start(ctx context.Context) error {
	opts := mqttlib.NewClientOptions().
		AddBroker(s.cfg.Broker).
		SetClientID(s.cfg.ClientID).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(s.cfg.ReconnectWait).
		SetMaxReconnectInterval(30 * time.Second).
		SetCleanSession(false).
		SetOrderMatters(false).
		SetOnConnectHandler(func(c mqttlib.Client) {
			s.connected.Store(true)
			s.log.Info("mqtt connected", "broker", s.cfg.Broker)
			if token := c.Subscribe(s.cfg.EventsTopic, 1, s.handle(ctx)); token.Wait() && token.Error() != nil {
				s.log.Error("mqtt subscribe failed", "topic", s.cfg.EventsTopic, "err", token.Error())
			} else {
				s.log.Info("mqtt subscribed", "topic", s.cfg.EventsTopic)
			}
		}).
		SetConnectionLostHandler(func(_ mqttlib.Client, err error) {
			s.connected.Store(false)
			s.log.Warn("mqtt connection lost", "err", err)
		})

	if s.cfg.Username != "" {
		opts.SetUsername(s.cfg.Username)
		opts.SetPassword(s.cfg.Password)
	}

	s.client = mqttlib.NewClient(opts)

	token := s.client.Connect()
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("mqtt connect timeout")
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("mqtt connect: %w", err)
	}
	return nil
}

func (s *Subscriber) handle(ctx context.Context) mqttlib.MessageHandler {
	return func(_ mqttlib.Client, msg mqttlib.Message) {
		if ctx.Err() != nil {
			return
		}
		s.onMsg(ctx, msg.Topic(), msg.Payload())
	}
}

func (s *Subscriber) Stop() {
	s.connected.Store(false)
	if s.client != nil && s.client.IsConnected() {
		s.client.Disconnect(500)
	}
}
