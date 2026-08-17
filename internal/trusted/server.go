package trusted

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/donovan-yohan/airlock/internal/paging"
)

const (
	csrfCookieName = "airlock_csrf"
	maxFormBytes   = 64 << 10
)

type Server struct {
	store   *Store
	dev     bool
	allowed map[string]bool
	csrf    string
	mux     *http.ServeMux
}

func NewServer(store *Store, allowedLogins []string, dev bool) (*Server, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	server := &Server{
		store: store, dev: dev, allowed: make(map[string]bool, len(allowedLogins)),
		csrf: base64.RawURLEncoding.EncodeToString(raw), mux: http.NewServeMux(),
	}
	for _, login := range allowedLogins {
		server.allowed[login] = true
	}
	server.mux.HandleFunc("/healthz", server.health)
	server.mux.HandleFunc("/requests/", server.requestRoute)
	server.mux.HandleFunc("/", server.home)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return trustedSecurityHeaders(s.mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		trustedMethodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"status\":\"ok\",\"role\":\"trusted\"}\n"))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		trustedMethodNotAllowed(w, http.MethodGet)
		return
	}
	reviewer, err := s.identity(r)
	if err != nil {
		http.Error(w, "trusted identity required", http.StatusUnauthorized)
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if key != "cursor" || len(values) != 1 {
			http.Error(w, "invalid review page query", http.StatusBadRequest)
			return
		}
	}
	cursor := query.Get("cursor")
	if !paging.ValidCursor(cursor) {
		http.Error(w, "invalid review page query", http.StatusBadRequest)
		return
	}
	records, nextCursor, err := s.store.RecordPage(paging.MaxPage, cursor)
	if err != nil {
		http.Error(w, "invalid review page cursor", http.StatusBadRequest)
		return
	}
	s.setCSRFCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = trustedHomePage.Execute(w, struct {
		Reviewer   string
		Records    []Record
		NextCursor string
		PageSize   int
	}{reviewer, records, nextCursor, paging.MaxPage})
}

func (s *Server) requestRoute(w http.ResponseWriter, r *http.Request) {
	reviewer, err := s.identity(r)
	if err != nil {
		http.Error(w, "trusted identity required", http.StatusUnauthorized)
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/requests/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method != http.MethodGet {
			trustedMethodNotAllowed(w, http.MethodGet)
			return
		}
		s.review(w, r, reviewer, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "decision" {
		if r.Method != http.MethodPost {
			trustedMethodNotAllowed(w, http.MethodPost)
			return
		}
		s.decision(w, r, reviewer, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) review(w http.ResponseWriter, _ *http.Request, reviewer, id string) {
	record, command, found := s.store.Record(id)
	if !found {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	s.setCSRFCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = trustedReviewPage.Execute(w, struct {
		Reviewer string
		Record   Record
		Command  string
		CSRF     string
	}{reviewer, record, command, s.csrf})
}

func (s *Server) decision(w http.ResponseWriter, r *http.Request, reviewer, id string) {
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not allowed", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "form content type required", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	for key, values := range r.PostForm {
		if (key != "csrf_token" && key != "decision") || len(values) != 1 {
			http.Error(w, "invalid form fields", http.StatusBadRequest)
			return
		}
	}
	if len(r.PostForm) < 2 || !s.validCSRF(r, r.PostForm.Get("csrf_token")) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site form refused", http.StatusForbidden)
		return
	}
	decision := r.PostForm.Get("decision")
	if _, err := s.store.Decide(id, decision, reviewer); err != nil {
		http.Error(w, "decision rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther)
}

func (s *Server) identity(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return "", errors.New("identity headers are accepted only from a loopback reverse proxy")
	}
	var header string
	if s.dev {
		if len(r.Header.Values("Tailscale-User-Login")) != 0 {
			return "", errors.New("Tailscale identity is not accepted in development mode")
		}
		header = "X-Airlock-Dev-Identity"
	} else {
		if len(r.Header.Values("X-Airlock-Dev-Identity")) != 0 {
			return "", errors.New("development identity is disabled")
		}
		header = "Tailscale-User-Login"
	}
	values := r.Header.Values(header)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] || !s.allowed[values[0]] {
		return "", errors.New("identity is absent or not allowlisted")
	}
	return values[0], nil
}

func (s *Server) setCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: s.csrf, Path: "/", HttpOnly: true,
		Secure: !s.dev, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) validCSRF(r *http.Request, formToken string) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || len(cookie.Value) != len(s.csrf) || len(formToken) != len(s.csrf) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.csrf)) == 1 &&
		subtle.ConstantTimeCompare([]byte(formToken), []byte(s.csrf)) == 1
}

func trustedSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func trustedMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

var trustedHomePage = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Airlock trusted review</title><style>
body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#18212f;background:#f7f8fa}article{background:white;border:1px solid #ccd5df;border-radius:.6rem;padding:1rem;margin:1rem 0}code{overflow-wrap:anywhere}.state{font-weight:700}.muted{color:#536273}a{color:#064f9e}
</style></head><body><h1>Airlock trusted review</h1><p>Signed in as <strong>{{.Reviewer}}</strong>.</p><p class="muted">This service renders commands for manual use and never executes them. Pages contain at most {{.PageSize}} requests.</p>{{if .Records}}{{range .Records}}<article><p class="state">{{.State}}</p><p><code>{{.Request.ID}}</code></p><p>{{.Request.Action}} on {{index .Request.Arguments "repository"}}</p><a href="/requests/{{.Request.ID}}">Review exact request</a></article>{{end}}{{else}}<p>No requests have been pulled.</p>{{end}}{{if .NextCursor}}<p><a href="/?cursor={{.NextCursor}}">Older requests →</a></p>{{end}}</body></html>`))

var trustedReviewPage = template.Must(template.New("review").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Airlock request review</title><style>
body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#18212f;background:#f7f8fa}section{background:white;border:1px solid #ccd5df;border-radius:.6rem;padding:1rem;margin:1rem 0}code,pre{overflow-wrap:anywhere;white-space:pre-wrap}dt{font-weight:700;margin-top:.8rem}button{padding:.6rem .9rem;margin:.4rem .4rem .4rem 0}textarea{display:block;width:100%;max-width:50rem}.warning{background:#fff4d6;border-color:#d59b22}
</style></head><body><p><a href="/">← All requests</a></p><h1>Trusted request review</h1><section><dl><dt>State</dt><dd>{{.Record.State}}</dd><dt>Request ID</dt><dd><code>{{.Record.Request.ID}}</code></dd><dt>Exact digest</dt><dd><code>{{.Record.Request.Digest}}</code></dd><dt>Action</dt><dd><code>{{.Record.Request.Action}}</code></dd><dt>Arguments</dt><dd>repository=<code>{{index .Record.Request.Arguments "repository"}}</code><br>permission=<code>{{index .Record.Request.Arguments "permission"}}</code></dd><dt>Reason</dt><dd>{{.Record.Request.Reason}}</dd><dt>Created</dt><dd>{{.Record.Request.CreatedAt}}</dd><dt>Expires</dt><dd>{{.Record.Request.ExpiresAt}}</dd></dl></section>
<section class="warning"><h2>Locally derived command</h2><p>Display/copy only. Airlock will not run this command.</p>{{if .Command}}<pre>{{.Command}}</pre>{{else}}<p>Request is not renderable by the installed adapter.</p>{{end}}</section>
{{if eq .Record.State "pending"}}<form method="post" action="/requests/{{.Record.Request.ID}}/decision"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="decision" value="approved_for_manual_execution">Approve for manual execution</button><button name="decision" value="denied">Deny</button></form>{{else if eq .Record.State "approved"}}<form method="post" action="/requests/{{.Record.Request.ID}}/decision"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="decision" value="manually_executed">Mark manually executed</button></form>{{end}}
{{if .Record.Receipts}}<section><h2>Signed receipts</h2>{{range .Record.Receipts}}<p><strong>{{.Receipt.Decision}}</strong> by {{.Receipt.Reviewer}} at {{.Receipt.CreatedAt}} — delivered: {{.Delivered}}</p>{{end}}</section>{{end}}</body></html>`))
