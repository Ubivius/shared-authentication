package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
)

var verifier *oidc.IDTokenVerifier
var ctx context.Context

func init() {
	//Authentication setup
	configURL := "http://keycloak/auth/realms/master"
	ctx = context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		log.Error(err, "Auth panic")
		panic(err)
	}

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	verifier = provider.Verifier(oidcConfig)
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawAccessToken := r.Header.Get("Authorization")
		if rawAccessToken == "" {
			log.Info("No access token provided")
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte("403 Forbidden"))
			if err != nil {
				panic(err)
			}
			return
		}

		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			log.Info("Missing token parts")
			w.WriteHeader(400)
			return
		}
		_, err := verifier.Verify(ctx, parts[1])
		if err != nil {
			log.Error(err, "Error while trying to access ressource")
			w.WriteHeader(400)
			_, err = w.Write([]byte("400 Bad Request"))
			if err != nil {
				panic(err)
			}
			return
		}
		log.Info("Serving http")
		next.ServeHTTP(w, r)
	})
}
