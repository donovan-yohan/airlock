package requester

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/donovan-yohan/airlock/internal/httpjson"
	"github.com/donovan-yohan/airlock/internal/model"
	"github.com/donovan-yohan/airlock/internal/paging"
)

type Server struct {
	store *Store
	mux   *http.ServeMux
}

func NewServer(store *Store) *Server {
	server := &Server{store: store, mux: http.NewServeMux()}
	server.mux.HandleFunc("/healthz", server.health)
	server.mux.HandleFunc("/api/v1/catalog", server.catalog)
	server.mux.HandleFunc("/api/v1/requests", server.requests)
	server.mux.HandleFunc("/api/v1/pending-requests", server.pendingRequests)
	server.mux.HandleFunc("/api/v1/requests/", server.request)
	server.mux.HandleFunc("/api/v1/receipts", server.receipts)
	server.mux.HandleFunc("/", server.home)
	return server
}

func (s *Server) pendingRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	limit, cursor, ok := recordPageQuery(r)
	if !ok {
		httpjson.Error(w, http.StatusBadRequest, "invalid pending request page")
		return
	}
	requests, nextCursor, err := s.store.ActionableRequestPage(limit, cursor)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid pending request page")
		return
	}
	httpjson.Write(w, http.StatusOK, pendingRequestPageResponse{Requests: requests, NextCursor: nextCursor})
}

type pendingRequestPageResponse struct {
	Requests   []model.Request `json:"requests"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"status": "ok", "role": "requester"})
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		catalog, found := s.store.Catalog()
		if !found {
			httpjson.Error(w, http.StatusNotFound, "no catalog installed")
			return
		}
		httpjson.Write(w, http.StatusOK, catalog)
	case http.MethodPost:
		var catalog model.Catalog
		if err := httpjson.Decode(w, r, &catalog); err != nil {
			httpjson.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.store.ImportCatalog(catalog); err != nil {
			if capacityUnavailable(w, err) {
				return
			}
			httpjson.Error(w, http.StatusUnprocessableEntity, "catalog rejected: "+err.Error())
			return
		}
		httpjson.Write(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) requests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, cursor, ok := recordPageQuery(r)
		if !ok {
			httpjson.Error(w, http.StatusBadRequest, "invalid request page")
			return
		}
		records, nextCursor, err := s.store.RecordPage(limit, cursor)
		if err != nil {
			httpjson.Error(w, http.StatusBadRequest, "invalid request page")
			return
		}
		httpjson.Write(w, http.StatusOK, recordPageResponse{Requests: records, NextCursor: nextCursor})
	case http.MethodPost:
		var input CreateInput
		if err := httpjson.Decode(w, r, &input); err != nil {
			httpjson.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		record, err := s.store.Create(input)
		if err != nil {
			if capacityUnavailable(w, err) {
				return
			}
			httpjson.Error(w, http.StatusUnprocessableEntity, "request rejected: "+err.Error())
			return
		}
		httpjson.Write(w, http.StatusCreated, record)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// recordPageResponse is the bounded wire shape of GET /api/v1/requests. The
// handler writes it and Client.Records decodes it, so it has one definition.
type recordPageResponse struct {
	Requests   []Record `json:"requests"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

func recordPageQuery(r *http.Request) (int, string, bool) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			return 0, "", false
		}
	}
	limit := DefaultRecordPage
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > MaxRecordPage {
			return 0, "", false
		}
		limit = parsed
	}
	cursor := query.Get("cursor")
	if !paging.ValidCursor(cursor) {
		return 0, "", false
	}
	return limit, cursor, true
}

func (s *Server) request(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/requests/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	record, found := s.store.Record(id)
	if !found {
		httpjson.Error(w, http.StatusNotFound, "request not found")
		return
	}
	httpjson.Write(w, http.StatusOK, record)
}

func (s *Server) receipts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var receipt model.Receipt
	if err := httpjson.Decode(w, r, &receipt); err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	record, err := s.store.AcceptReceipt(receipt)
	if err != nil {
		if capacityUnavailable(w, err) {
			return
		}
		httpjson.Error(w, http.StatusUnprocessableEntity, "receipt rejected: "+err.Error())
		return
	}
	httpjson.Write(w, http.StatusAccepted, record)
}

func capacityUnavailable(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, ErrCapacity) {
		return false
	}
	httpjson.Error(w, http.StatusServiceUnavailable, "requester capacity unavailable")
	return true
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if key != "cursor" || len(values) != 1 {
			http.Error(w, "invalid requester page query", http.StatusBadRequest)
			return
		}
	}
	cursor := query.Get("cursor")
	if !paging.ValidCursor(cursor) {
		http.Error(w, "invalid requester page query", http.StatusBadRequest)
		return
	}
	records, nextCursor, err := s.store.RecordPage(DefaultRecordPage, cursor)
	if err != nil {
		http.Error(w, "invalid requester page cursor", http.StatusBadRequest)
		return
	}
	catalog, _ := s.store.Catalog()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = requesterPage.Execute(w, struct {
		Catalog    *model.Catalog
		Records    []Record
		NextCursor string
		PageSize   int
	}{catalog, records, nextCursor, DefaultRecordPage})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	httpjson.Error(w, http.StatusMethodNotAllowed, "method not allowed")
}

var requesterPage = template.Must(template.New("requester").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Airlock requester</title><style>
body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#18212f;background:#f7f8fa}h1,h2{color:#10253f}article{background:white;border:1px solid #ccd5df;border-radius:.6rem;padding:1rem;margin:1rem 0}code{overflow-wrap:anywhere}.state{font-weight:700}.muted{color:#536273}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:.45rem;border-bottom:1px solid #dde3ea}
</style></head><body><h1>Airlock requester</h1><p class="muted">Read-only status. Decisions are available only on the trusted node.</p>
<h2>Signed catalog</h2>{{if .Catalog}}<article><p><strong>Valid until:</strong> {{.Catalog.ExpiresAt}}</p>{{range .Catalog.Profiles}}<h3>{{.DisplayName}}</h3><p><code>{{.ID}}/{{.Version}}</code></p><p>{{.AuthorityLabel}} · {{.SandboxLabel}} · {{.OutputLabel}}</p>{{end}}{{if .Catalog.Capabilities}}<p class="muted">Historical typed capabilities are retained as compatibility data.</p>{{end}}</article>{{else}}<p>No catalog installed.</p>{{end}}
<h2>Requests</h2><p class="muted">Pages contain at most {{.PageSize}} requests. Executable paths, environment, credential locations, and raw output never appear here.</p>{{if .Records}}{{range .Records}}<article><p class="state">{{.State}}</p><p><strong>ID:</strong> <code>{{.Request.ID}}</code></p><p><strong>Digest:</strong> <code>{{.Request.Digest}}</code></p>{{if .Request.ProfileID}}<p><strong>Profile:</strong> <code>{{.Request.ProfileID}}/{{.Request.ProfileVersion}}</code></p><p><strong>Argv element count:</strong> {{len .Request.Argv}}</p>{{else}}<p><strong>Historical action:</strong> <code>{{.Request.Action}}</code></p>{{end}}<p><strong>Reason:</strong> {{.Request.Reason}}</p><p><strong>Expires:</strong> {{.Request.ExpiresAt}}</p>{{if .Receipts}}<table><tr><th>Decision</th><th>Reviewer</th><th>Plan digest</th><th>Time</th></tr>{{range .Receipts}}<tr><td>{{.Decision}}</td><td>{{.Reviewer}}</td><td>{{.PlanDigest}}</td><td>{{.CreatedAt}}</td></tr>{{end}}</table>{{end}}</article>{{end}}{{else}}<p>No requests.</p>{{end}}{{if .NextCursor}}<p><a href="/?cursor={{.NextCursor}}">Older requests →</a></p>{{end}}</body></html>`))
