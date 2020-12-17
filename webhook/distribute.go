package webhook

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"go.ketch.com/lib/orlop/errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

// Send an event to the webhook
func (s *Client) Send(ctx context.Context, event *cloudevents.Event) error {
	var err error
	var body []byte
	var contentType string

	switch s.mode {
	case Structured:
		contentType = "application/cloudevents+json; charset=UTF-8"
		if body, err = json.Marshal(event); err != nil {
			return wrapPermanentWebhookError(errors.Wrap(err, "failed to marshal event"))
		}

	default:
		body = event.Data()
		contentType = event.DataContentType()
	}

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewBuffer(body))
	if err != nil {
		return newRetryableWebhookError("failed to create request")
	}

	// Fill in the shared headers
	for k, vv := range s.Headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// If the mode is binary, we need to put the event properties in headers
	if s.mode == Binary {
		req.Header.Set("ce-specversion", event.SpecVersion())
		req.Header.Set("ce-id", event.ID())
		req.Header.Set("ce-time", event.Time().Format(time.RFC3339))
		req.Header.Set("ce-type", event.Type())
		req.Header.Set("ce-source", event.Source())
		req.Header.Set("ce-subject", event.Subject())

		if len(event.DataSchema()) > 0 {
			req.Header.Set("ce-dataschema", event.DataSchema())
		}

		for k, v := range event.Extensions() {
			req.Header.Set(http.CanonicalHeaderKey(fmt.Sprintf("ce-%s", k)), fmt.Sprintf("%v", v))
		}
	}

	req.Header.Set("Content-Type", contentType)

	// If a secret key is specified, sign the body
	if len(s.secret) != 0 {
		req.Header.Set("X-Hub-Signature", s.sign(sha1.New, body))
		req.Header.Set("X-Hub-Signature-256", s.sign(sha256.New, body))
	}

	// Send the request
	resp, err := s.cli.Do(req)
	if resp != nil && resp.Body != nil {
		defer func() {
			if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
				s.logger.WithError(err).Error("failed to consume body")
			}
		}()
	}

	if err != nil {
		return wrapRetryableWebhookError(errors.Wrap(err, "failed to connect"))
	}

	// Check that the response code is as expected
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:

	case http.StatusCreated, http.StatusAccepted:
		return Accepted

	case http.StatusMethodNotAllowed:
		return NotAllowedError

	case http.StatusTooManyRequests:
		return BackoffError

	case http.StatusGone:
		return GoneError

	case http.StatusUnsupportedMediaType:
		return UnsupportedMediaError

	default:
		err = errors.Errorf("bad response %s", resp.Status)
		if resp.StatusCode >= 500 {
			return wrapRetryableWebhookError(err)
		} else {
			return wrapPermanentWebhookError(err)
		}
	}

	return nil
}
