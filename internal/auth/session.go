package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/JeffResc/AuthStep/internal/store"
)

type ctxKey struct{}

// SessionFrom returns the request's session, or nil when signed out.
func SessionFrom(ctx context.Context) *store.Session {
	s, _ := ctx.Value(ctxKey{}).(*store.Session)
	return s
}

// Session loads the session named by the session cookie into the request
// context. Expired sessions are deleted and their cookie cleared.
func (a *Auth) Session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		hash := hashToken(c.Value)
		sess, err := a.store.SessionByHash(r.Context(), hash)
		if errors.Is(err, store.ErrNotFound) {
			clearCookie(w, sessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}

		now := a.now()
		if now.Sub(sess.LastSeenAt) > SessionIdle || now.Sub(sess.CreatedAt) > SessionMax {
			if err := a.store.DeleteSession(r.Context(), hash); err != nil {
				a.fail(w, r, err)
				return
			}
			clearCookie(w, sessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		if now.Sub(sess.LastSeenAt) > touchInterval {
			if err := a.store.TouchSession(r.Context(), hash, now); err != nil {
				a.fail(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

// CSRF rejects state-changing requests from a signed-in user that do not
// carry the session's CSRF token in the X-CSRF-Token header or the
// csrf_token form field. Requests without a session have nothing to forge;
// handlers that need a user enforce that themselves.
func (a *Auth) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFrom(r.Context())
		if sess == nil || isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get(CSRFHeader)
		if token == "" {
			token = r.PostFormValue(CSRFFormField)
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
			a.log.Warn("csrf token mismatch", "sub", sess.User.Sub, "path", r.URL.Path)
			a.Denied(w, r, http.StatusForbidden, "This request could not be verified. Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
