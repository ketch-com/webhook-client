package webhook

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"go.ketch.com/lib/orlop"
	"go.ketch.com/lib/orlop/log"
	"go.ketch.com/lib/webhook-client/version"
	"hash"
	"net/http"
)

const (
	SecretKey        = "secret"
	AuthorizationKey = "authorization"
	Origin           = "hoist.ketch.com"
	GangplankOrigin  = "gangplank.ketch.com"
)

type Mode int
const (
	Binary Mode = iota
	Structured
)

// Client is a client for sending requests to Webhooks
type Client struct {
	cli     *http.Client
	Headers http.Header
	secret  []byte
	logger  *logrus.Entry
	mode    Mode
	url     string
	maxQPS  uint64
}

// NewClient returns a new Webhook Client
func NewClient(ctx context.Context, mode Mode, url string, maxQPS uint64, tls *orlop.TLSConfig, auth *orlop.KeyConfig,
	secret *orlop.KeyConfig, vault orlop.HasVaultConfig, origin string) (*Client, error) {

	s := &Client{
		mode:    mode,
		cli:     &http.Client{},
		Headers: make(http.Header),
		logger:  log.FromContext(ctx).WithField("client", "webhook"),
		url:     url,
		maxQPS:  maxQPS,
	}

	s.Headers.Set("User-Agent", fmt.Sprintf("%s/%s", version.Name, version.Version))
	s.Headers.Add("Origin", origin)
	s.Headers.Add("WebHook-Request-Origin", origin)
	s.Headers.Add("WebHook-Request-Rate", fmt.Sprintf("%d", maxQPS))
	s.Headers.Add("Cache-Control", "no-store")

	if tls != nil {
		t, err := orlop.NewClientTLSConfigContext(ctx, tls, vault)
		if err != nil {
			return nil, err
		}

		s.cli.Transport = &http.Transport{
			TLSClientConfig: t,
		}
	}

	b, err := orlop.LoadKeyContext(ctx, auth, vault, AuthorizationKey)
	if err != nil {
		log.WithError(err).Error("failed to load Authorization token")
	}

	if len(b) > 0 {
		s.Headers.Add("Authorization", string(b))
	}

	if s.secret, err = orlop.LoadKeyContext(ctx, secret, vault, SecretKey); err != nil {
		return nil, err
	}

	return s, nil
}

// MaxQPS returns the current maximum QPS setting
func (s *Client) MaxQPS() uint64 {
	return s.maxQPS
}

func (s *Client) sign(alg func() hash.Hash, body []byte) string {
	h := hmac.New(alg, s.secret)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
