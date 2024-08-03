package rest

const (
	StatusUnauthorized        = "Unauthorized"
	StatusForbidden           = "StatusForbidden"
	StatusNotFound            = "NotFound"
	StatusInternalServerError = "InternalServerError"
)

const (
	ErrCertIsNeeded = "cert is needed"
	ErrCertInvalid  = "failed to verify client certificate"
	ErrNotFound     = "the requested resource is not found"
	ErrForbidden    = "the requested resource is forbidden"
)
