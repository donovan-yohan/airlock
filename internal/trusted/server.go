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
	service *ActionService
	dev     bool
	allowed map[string]bool
	csrf    string
	mux     *http.ServeMux
}

func NewServer(store *Store, allowedLogins []string, dev bool) (*Server, error) {
	return NewServerWithActionService(NewActionService(store), allowedLogins, dev)
}

func NewServerWithActionService(service *ActionService, allowedLogins []string, dev bool) (*Server, error) {
	if service == nil {
		return nil, errors.New("trusted action service is required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	server := &Server{
		service: service, dev: dev, allowed: make(map[string]bool, len(allowedLogins)),
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
	records, nextCursor, err := s.service.RecordPage(cursor)
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
	if len(parts) == 2 && parts[0] != "" && parts[1] == "execute" {
		if r.Method != http.MethodPost {
			trustedMethodNotAllowed(w, http.MethodPost)
			return
		}
		s.execute(w, r, reviewer, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "deny" {
		if r.Method != http.MethodPost {
			trustedMethodNotAllowed(w, http.MethodPost)
			return
		}
		s.deny(w, r, reviewer, parts[0])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) review(w http.ResponseWriter, _ *http.Request, reviewer, id string) {
	record, plan, found := s.service.Record(id)
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
		Plan     *ExecutionPlan
		Command  string
		Warnings []string
		CSRF     string
	}{reviewer, record, plan, func() string {
		if plan == nil {
			return ""
		}
		return escapedCommand(*plan)
	}(), func() []string {
		if plan == nil {
			return nil
		}
		return classifyGitHubRisk(plan.Argv)
	}(), s.csrf})
}

func (s *Server) validateTrustedForm(w http.ResponseWriter, r *http.Request, requirePlan, requireFullAuthority bool) (string, bool) {
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not allowed", http.StatusBadRequest)
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "form content type required", http.StatusUnsupportedMediaType)
		return "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return "", false
	}
	for key, values := range r.PostForm {
		if (key != "csrf_token" && key != "plan_digest" && key != "confirm_full_authority") || len(values) != 1 {
			http.Error(w, "invalid form fields", http.StatusBadRequest)
			return "", false
		}
	}
	expectedFields := 1
	if requirePlan {
		expectedFields = 2
	}
	if requireFullAuthority {
		expectedFields++
	}
	planDigest := r.PostForm.Get("plan_digest")
	if len(r.PostForm) != expectedFields || (requirePlan && len(planDigest) != 64) || (requireFullAuthority && r.PostForm.Get("confirm_full_authority") != "true") || !s.validCSRF(r, r.PostForm.Get("csrf_token")) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return "", false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site form refused", http.StatusForbidden)
		return "", false
	}
	return planDigest, true
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, reviewer, id string) {
	planDigest, ok := s.validateTrustedForm(w, r, true, true)
	if !ok {
		return
	}
	if err := s.service.Execute(r.Context(), id, reviewer, planDigest, true); err != nil {
		// Errors can originate in a local child process. Keep those details out
		// of the UI; the bounded stored status is the reviewer-facing evidence.
		http.Error(w, "trusted execution was not completed; inspect the bounded attempt status before an explicit retry", http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther)
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, reviewer, id string) {
	if _, ok := s.validateTrustedForm(w, r, false, false); !ok {
		return
	}
	if err := s.service.Deny(id, reviewer); err != nil {
		http.Error(w, "decision rejected", http.StatusUnprocessableEntity)
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
</style></head><body><h1>Airlock trusted review</h1><p>Signed in as <strong>{{.Reviewer}}</strong>.</p><p class="muted">Airlock validates a command proposal, persists a reviewer-approved exact resolved plan, then directly executes its argv without shell parsing. Pages contain at most {{.PageSize}} requests.</p>{{if .Records}}{{range .Records}}<article><p class="state">{{.State}}</p><p><code>{{.Request.ID}}</code></p>{{if .Request.ProfileID}}<p><code>{{.Request.ProfileID}}/{{.Request.ProfileVersion}}</code> — {{len .Request.Argv}} argv elements</p>{{else}}<p>Historical <code>{{.Request.Action}}</code> request</p>{{end}}<a href="/requests/{{.Request.ID}}">Review exact request</a></article>{{end}}{{else}}<p>No requests have been pulled.</p>{{end}}{{if .NextCursor}}<p><a href="/?cursor={{.NextCursor}}">Older requests →</a></p>{{end}}</body></html>`))

var trustedReviewPage = template.Must(template.New("review").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Airlock request review</title><style>
body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#18212f;background:#f7f8fa}section{background:white;border:1px solid #ccd5df;border-radius:.6rem;padding:1rem;margin:1rem 0}code,pre{overflow-wrap:anywhere;white-space:pre-wrap}dt{font-weight:700;margin-top:.8rem}button{padding:.6rem .9rem;margin:.4rem .4rem .4rem 0}textarea{display:block;width:100%;max-width:50rem}.warning{background:#fff4d6;border-color:#d59b22}
</style></head><body><p><a href="/">← All requests</a></p><h1>Trusted request review</h1><section><dl><dt>State</dt><dd>{{.Record.State}}</dd><dt>Request ID</dt><dd><code>{{.Record.Request.ID}}</code></dd><dt>Exact request digest</dt><dd><code>{{.Record.Request.Digest}}</code></dd>{{if .Record.Request.ProfileID}}<dt>Proposed profile</dt><dd><code>{{.Record.Request.ProfileID}}/{{.Record.Request.ProfileVersion}}</code></dd>{{else}}<dt>Historical action</dt><dd><code>{{.Record.Request.Action}}</code></dd>{{end}}<dt>Reason</dt><dd>{{.Record.Request.Reason}}</dd><dt>Created</dt><dd>{{.Record.Request.CreatedAt}}</dd><dt>Expires</dt><dd>{{.Record.Request.ExpiresAt}}</dd></dl></section>
<section class="warning"><h2>Resolved immutable plan</h2>{{if .Plan}}<dl><dt>Profile</dt><dd><code>{{.Plan.ProfileID}}/{{.Plan.ProfileVersion}}</code></dd><dt>Authority</dt><dd>{{.Plan.CredentialAuthority}}</dd><dt>Request digest</dt><dd><code>{{.Plan.RequestDigest}}</code></dd><dt>Resolved plan digest</dt><dd><code>{{.Plan.Digest}}</code></dd><dt>Executable path</dt><dd><code>{{.Plan.Executable}}</code></dd><dt>Executable SHA-256 identity</dt><dd><code>{{.Plan.ExecutableSHA256}}</code></dd><dt>Credential snapshot identity</dt><dd><code>{{.Plan.CredentialSourceID}}</code></dd><dt>Sandbox launcher path</dt><dd><code>{{.Plan.SandboxLauncher}}</code></dd><dt>Sandbox launcher SHA-256 identity</dt><dd><code>{{.Plan.SandboxLauncherSHA256}}</code></dd><dt>Execution identity</dt><dd>{{.Plan.ExecutionIdentity}}</dd><dt>Sandbox</dt><dd>{{.Plan.SandboxPolicy}}</dd><dt>Network</dt><dd>{{.Plan.NetworkPolicy}}</dd><dt>Working directory</dt><dd>{{.Plan.WorkingDirectoryPolicy}}</dd><dt>Environment policy</dt><dd><ul>{{range .Plan.EnvironmentPolicy}}<li><code>{{.}}</code></li>{{end}}</ul></dd><dt>Timeout</dt><dd>{{.Plan.TimeoutMilliseconds}} ms</dd><dt>Output</dt><dd>{{.Plan.OutputPolicy}}</dd><dt>Profile config version</dt><dd><code>{{.Plan.ProfileConfigVersion}}</code></dd></dl><h3>Exact argv elements</h3><ol start="0">{{range $index, $argument := .Plan.Argv}}<li><code>argv[{{$index}}] = {{$argument}}</code></li>{{end}}</ol><p>Non-executable escaped convenience rendering:</p><pre>{{.Command}}</pre><h3>Reviewer-assistance warnings</h3><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>Request is not renderable by the installed profile. Execution is unavailable.</p>{{end}}</section>
{{if and .Plan (eq .Record.State "pending")}}<form method="post" action="/requests/{{.Record.Request.ID}}/execute"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="plan_digest" value="{{.Plan.Digest}}"><p class="warning"><label><input type="checkbox" name="confirm_full_authority" value="true"> I confirm this exact plan grants full configured GitHub authority and may have high impact.</label></p><button>Approve exact plan and execute</button></form><form method="post" action="/requests/{{.Record.Request.ID}}/deny"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button>Deny and require resubmission</button></form>{{else if and .Plan (or (eq .Record.State "failed") (eq .Record.State "uncertain"))}}<form method="post" action="/requests/{{.Record.Request.ID}}/execute"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="plan_digest" value="{{.Plan.Digest}}"><p class="warning"><label><input type="checkbox" name="confirm_full_authority" value="true"> I confirm this exact retry grants full configured GitHub authority and may have high impact.</label></p><button>Approve exact plan and retry</button></form>{{else if eq .Record.State "running"}}<p class="warning">An execution attempt is running. Refresh for its bounded result; no concurrent attempt can start.</p>{{else if eq .Record.State "executed"}}<p class="warning"><strong>Local execution succeeded; this does not prove GitHub state.</strong> Verify the intended effect through an independent read-only provider check.</p>{{end}}
{{if .Record.Attempts}}<section><h2>Bounded local execution attempts</h2>{{range .Record.Attempts}}<p><strong>{{.Status}}</strong> — {{.ID}} — started {{.StartedAt}}{{if .FinishedAt}}, finished {{.FinishedAt}}{{end}}{{if .FailureCode}}, code {{.FailureCode}}{{end}}</p>{{if .Plan}}<section><h3>Immutable plan approved for this attempt</h3><dl><dt>Plan digest</dt><dd><code>{{.Plan.Digest}}</code></dd><dt>Executable</dt><dd><code>{{.Plan.Executable}}</code></dd><dt>Executable SHA-256</dt><dd><code>{{.Plan.ExecutableSHA256}}</code></dd><dt>Credential snapshot identity</dt><dd><code>{{.Plan.CredentialSourceID}}</code></dd><dt>Sandbox launcher</dt><dd><code>{{.Plan.SandboxLauncher}}</code></dd><dt>Sandbox launcher SHA-256</dt><dd><code>{{.Plan.SandboxLauncherSHA256}}</code></dd><dt>Environment policy</dt><dd><ul>{{range .Plan.EnvironmentPolicy}}<li><code>{{.}}</code></li>{{end}}</ul></dd><dt>Timeout</dt><dd>{{.Plan.TimeoutMilliseconds}} ms</dd><dt>Output</dt><dd>{{.Plan.OutputPolicy}}</dd><dt>Profile config version</dt><dd><code>{{.Plan.ProfileConfigVersion}}</code></dd></dl><h4>Exact argv elements</h4><ol start="0">{{range $index, $argument := .Plan.Argv}}<li><code>argv[{{$index}}] = {{$argument}}</code></li>{{end}}</ol></section>{{end}}{{if .OutputPreview}}<section class="warning"><h3>Trusted-local captured output</h3><p>Visible only to this trusted reviewer surface; sanitized before storage{{if .OutputPreview.Redacted}}; credential-like text redacted{{end}}{{if .OutputPreview.StdoutTruncated}}; stdout truncated{{end}}{{if .OutputPreview.StderrTruncated}}; stderr truncated{{end}}.</p>{{if .OutputPreview.Stdout}}<h4>stdout</h4><pre>{{.OutputPreview.Stdout}}</pre>{{end}}{{if .OutputPreview.Stderr}}<h4>stderr</h4><pre>{{.OutputPreview.Stderr}}</pre>{{end}}</section>{{end}}{{end}}</section>{{end}}{{if .Record.Receipts}}<section><h2>Signed receipts</h2>{{range .Record.Receipts}}<p><strong>{{.Receipt.Decision}}</strong> by {{.Receipt.Reviewer}} at {{.Receipt.CreatedAt}} — delivered: {{.Delivered}}</p>{{end}}</section>{{end}}</body></html>`))
