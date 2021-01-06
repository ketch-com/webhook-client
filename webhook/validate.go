package webhook

import (
	"context"
	"go.ketch.com/lib/orlop/errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// Validate a webhook target
func (s *Client) Validate(ctx context.Context) error {
	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, s.url, nil)
	if err != nil {
		return wrapRetryableWebhookError(errors.New("failed to create request"))
	}

	// Add our shared headers
	for k, vv := range s.Headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
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

	// Check that the response code is expected
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusAccepted:

	case http.StatusMethodNotAllowed:
		return NotAllowedError

	case http.StatusGone:
		return GoneError

	case http.StatusUnsupportedMediaType:
		return UnsupportedMediaError

	case http.StatusTooManyRequests:
		return BackoffError

	default:
		err = errors.Errorf("bad response %s", resp.Status)
		if resp.StatusCode >= 500 {
			return wrapRetryableWebhookError(err)
		} else {
			return wrapPermanentWebhookError(err)
		}
	}

	// Check that the Origin has been validated
	allowedOrigin := resp.Header.Get("WebHook-Allowed-Origin")
	if allowedOrigin != Origin && allowedOrigin != "*" && allowedOrigin != GangplankOrigin {
		return newPermanentWebhookError("blocked because WebHook-Allowed-Origin header did not include our origin")
	}

	// Check that the requested rate has been validated
	allowedRate := resp.Header.Get("WebHook-Allowed-Rate")
	if len(allowedRate) > 0 {
		if rate, err := strconv.ParseUint(allowedRate, 10, 64); err != nil {
			return newPermanentWebhookError("blocked because WebHook-Allowed-Rate header could not be parsed")
		} else if rate < s.maxQPS {
			s.maxQPS = rate
		}
	}

	// Check that the POST method has been Allowed
	allowedMethods := resp.Header.Get("Allow")
	if !strings.Contains(allowedMethods, "POST") {
		return newPermanentWebhookError("blocked because Allow header did not include POST method")
	}

	return nil
}
