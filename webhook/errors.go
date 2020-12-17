package webhook

import "go.ketch.com/lib/orlop/errors"

var (
	Accepted              = errors.New("accepted")
	BackoffError          = newRetryableWebhookError("too many requests")
	NotAllowedError       = newPermanentWebhookError("not allowed")
	GoneError             = newPermanentWebhookError("webhook no longer exists")
	UnsupportedMediaError = newPermanentWebhookError("webhook does not support this content type")
)

type Error interface {
	Retryable() bool
}

type webhookError struct {
	retryable bool
	err       error
}

func IsRetryable(err error) bool {
	if e, ok := err.(Error); ok {
		return e.Retryable()
	} else {
		return false
	}
}

var _ Error = &webhookError{}
var _ error = &webhookError{}
var _ interface {
	Unwrap() error
} = &webhookError{}

func (e *webhookError) Retryable() bool {
	return e.retryable
}

func (e *webhookError) Error() string {
	return e.err.Error()
}

func (e *webhookError) Unwrap() error {
	return e.err
}

func newRetryableWebhookError(message string) error {
	return &webhookError{
		retryable: true,
		err:       errors.New(message),
	}
}

func newPermanentWebhookError(message string) error {
	return &webhookError{
		retryable: true,
		err:       errors.New(message),
	}
}

func wrapRetryableWebhookError(err error) error {
	return &webhookError{
		retryable: true,
		err:       err,
	}
}

func wrapPermanentWebhookError(err error) error {
	return &webhookError{
		retryable: false,
		err:       err,
	}
}
