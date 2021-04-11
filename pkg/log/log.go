package log

import (
	logf "sigs.k8s.io/shared-authentication/pkg/log"
)

// MLog is a base parent logger for the microservice
var MLog = logf.Log.WithName("auth-middlware")
