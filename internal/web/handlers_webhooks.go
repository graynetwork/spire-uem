package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/webhooks"
)

// Event webhook administration. All routes are SUPER_ADMIN only (router.go) and mutations
// carry CSRF like the rest of /admin. A response is HTML only when the client asks for
// text/html; everything else gets JSON. The signing secret is returned exactly once, by
// create and rotate, and never by any GET.

// webhookJSON is the admin-facing subscription shape. It has no secret field at all.
type webhookJSON struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	URL                 string    `json:"url"`
	EventTypes          []string  `json:"event_types"`
	TagScope            []string  `json:"tag_scope"`
	Enabled             bool      `json:"enabled"`
	AllowPrivateNetwork bool      `json:"allow_private_network"`
	HasSecret           bool      `json:"has_secret"`
	SecretRotatedAt     time.Time `json:"secret_rotated_at"`
	ConsecutiveDead     int       `json:"consecutive_dead"`
	DisabledReason      string    `json:"disabled_reason,omitempty"`
	CreatedBy           string    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func toWebhookJSON(s db.WebhookSubscription) webhookJSON {
	return webhookJSON{
		ID: s.ID, Name: s.Name, URL: s.URL, EventTypes: s.EventTypes, TagScope: s.TagScope,
		Enabled: s.Enabled, AllowPrivateNetwork: s.AllowPrivateNetwork, HasSecret: true,
		SecretRotatedAt: s.SecretRotatedAt, ConsecutiveDead: s.ConsecutiveDead,
		DisabledReason: s.DisabledReason, CreatedBy: s.CreatedBy, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

type webhookDeliveryJSON struct {
	ID             string               `json:"id"`
	EventID        string               `json:"event_id"`
	EventType      string               `json:"event_type"`
	Status         string               `json:"status"`
	Attempts       int                  `json:"attempts"`
	NextAttemptAt  time.Time            `json:"next_attempt_at"`
	LastStatusCode *int                 `json:"last_status_code,omitempty"`
	LastError      string               `json:"last_error,omitempty"`
	RedeliveryOf   *string              `json:"redelivery_of,omitempty"`
	CreatedAt      time.Time            `json:"created_at"`
	FinishedAt     *time.Time           `json:"finished_at,omitempty"`
	AttemptLog     []webhookAttemptJSON `json:"attempt_log,omitempty"`
}

type webhookAttemptJSON struct {
	AttemptNo       int       `json:"attempt_no"`
	StartedAt       time.Time `json:"started_at"`
	DurationMS      int       `json:"duration_ms"`
	StatusCode      *int      `json:"status_code,omitempty"`
	Error           string    `json:"error,omitempty"`
	ResponseSnippet string    `json:"response_snippet,omitempty"`
}

func writeWebhookJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func webhookError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsHTML(r) {
		http.Error(w, msg, status)
		return
	}
	writeWebhookJSON(w, status, map[string]any{"error": msg})
}

// webhookInputFromRequest reads a subscription definition from a JSON body or a form.
func webhookInputFromRequest(w http.ResponseWriter, r *http.Request) (db.WebhookInput, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			Name                string   `json:"name"`
			URL                 string   `json:"url"`
			EventTypes          []string `json:"event_types"`
			TagScope            []string `json:"tag_scope"`
			Enabled             *bool    `json:"enabled"`
			AllowPrivateNetwork bool     `json:"allow_private_network"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return db.WebhookInput{}, errors.New("invalid JSON body")
		}
		en := true
		if req.Enabled != nil {
			en = *req.Enabled
		}
		return db.WebhookInput{Name: req.Name, URL: req.URL, EventTypes: req.EventTypes,
			TagScope: req.TagScope, Enabled: en, AllowPrivateNetwork: req.AllowPrivateNetwork}, nil
	}
	if err := r.ParseForm(); err != nil {
		return db.WebhookInput{}, errors.New("invalid form")
	}
	return db.WebhookInput{
		Name:                r.FormValue("name"),
		URL:                 r.FormValue("url"),
		EventTypes:          r.Form["event_types"],
		TagScope:            splitRecipients(r.FormValue("tag_scope")),
		Enabled:             alertFormBool(r.FormValue("enabled")),
		AllowPrivateNetwork: alertFormBool(r.FormValue("allow_private_network")),
	}, nil
}

func (h *Handler) auditWebhook(r *http.Request, action, target string, details map[string]any) {
	// Reuses the alert audit helper; details never contain secrets.
	h.auditAlert(r, action, target, details)
}

// WebhooksPage handles GET /admin/webhooks (JSON list unless the client accepts text/html).
// With ?sub=<id> the HTML page also shows that subscription's delivery log.
func (h *Handler) WebhooksPage(w http.ResponseWriter, r *http.Request) {
	st := h.repo.WebhookStore()
	subs, err := st.ListSubscriptions(r.Context())
	if err != nil {
		log.Printf("[web] list webhooks: %v", err)
		webhookError(w, r, http.StatusInternalServerError, "failed to load webhooks")
		return
	}
	if !wantsHTML(r) {
		out := make([]webhookJSON, 0, len(subs))
		for _, s := range subs {
			out = append(out, toWebhookJSON(s))
		}
		writeWebhookJSON(w, http.StatusOK, map[string]any{"webhooks": out})
		return
	}
	h.renderWebhooksPage(w, r, subs, nil)
}

// webhookView adds template helpers to the JSON shape.
type webhookView struct {
	webhookJSON
	EventSet    map[string]bool
	TagScopeStr string
}

type webhookFlashSecret struct {
	SubscriptionName string
	Secret           string
	Rotated          bool
}

func (h *Handler) renderWebhooksPage(w http.ResponseWriter, r *http.Request, subs []db.WebhookSubscription, secret *webhookFlashSecret) {
	st := h.repo.WebhookStore()
	var selected *db.WebhookSubscription
	var deliveries []webhookDeliveryJSON
	if id := r.URL.Query().Get("sub"); id != "" {
		for i := range subs {
			if subs[i].ID == id {
				selected = &subs[i]
			}
		}
		if selected != nil {
			rows, err := st.ListDeliveries(r.Context(), selected.ID, 25)
			if err != nil {
				log.Printf("[web] list webhook deliveries: %v", err)
			}
			for _, d := range rows {
				dj := deliveryToJSON(d)
				if atts, err := st.ListAttempts(r.Context(), d.ID); err == nil {
					dj.AttemptLog = attemptsToJSON(atts)
				}
				deliveries = append(deliveries, dj)
			}
		}
	}
	views := make([]webhookView, 0, len(subs))
	for _, s := range subs {
		v := webhookView{webhookJSON: toWebhookJSON(s), EventSet: map[string]bool{}, TagScopeStr: strings.Join(s.TagScope, ", ")}
		for _, t := range s.EventTypes {
			v.EventSet[t] = true
		}
		views = append(views, v)
	}
	data := map[string]any{
		"Title":        "Event webhooks",
		"ActiveNav":    "webhooks",
		"CSRFToken":    CSRFTokenFromContext(r.Context()),
		"AdminUser":    AdminUserFromContext(r.Context()),
		"AdminRole":    AdminRoleFromContext(r.Context()),
		"Webhooks":     views,
		"Catalog":      webhooks.Catalog,
		"Selected":     selected,
		"Deliveries":   deliveries,
		"NewSecret":    secret,
		"FlashMessage": r.URL.Query().Get("msg"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render webhooks page: %v", err)
	}
}

func deliveryToJSON(d db.WebhookDeliveryRow) webhookDeliveryJSON {
	return webhookDeliveryJSON{ID: d.ID, EventID: d.EventID, EventType: d.EventType, Status: d.Status,
		Attempts: d.Attempts, NextAttemptAt: d.NextAttemptAt, LastStatusCode: d.LastStatusCode,
		LastError: d.LastError, RedeliveryOf: d.RedeliveryOf, CreatedAt: d.CreatedAt, FinishedAt: d.FinishedAt}
}

func attemptsToJSON(in []db.WebhookAttemptRow) []webhookAttemptJSON {
	out := make([]webhookAttemptJSON, 0, len(in))
	for _, a := range in {
		out = append(out, webhookAttemptJSON{AttemptNo: a.AttemptNo, StartedAt: a.StartedAt,
			DurationMS: a.DurationMS, StatusCode: a.StatusCode, Error: a.Error, ResponseSnippet: a.ResponseSnippet})
	}
	return out
}

// CreateWebhook handles POST /admin/webhooks.
func (h *Handler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	in, err := webhookInputFromRequest(w, r)
	if err != nil {
		webhookError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	sub, secret, err := h.repo.WebhookStore().CreateSubscription(r.Context(), in, AdminUserFromContext(r.Context()))
	if err != nil {
		webhookError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	h.auditWebhook(r, "WEBHOOK_CREATE", sub.ID, map[string]any{
		"name": sub.Name, "url": sub.URL, "event_types": sub.EventTypes, "tag_scope": sub.TagScope,
		"allow_private_network": sub.AllowPrivateNetwork,
	})
	if sub.AllowPrivateNetwork {
		h.auditWebhook(r, "WEBHOOK_ALLOW_PRIVATE_NETWORK", sub.ID, map[string]any{"name": sub.Name, "allow": true})
	}
	if wantsHTML(r) {
		subs, _ := h.repo.WebhookStore().ListSubscriptions(r.Context())
		h.renderWebhooksPage(w, r, subs, &webhookFlashSecret{SubscriptionName: sub.Name, Secret: secret})
		return
	}
	writeWebhookJSON(w, http.StatusCreated, map[string]any{
		"webhook": toWebhookJSON(*sub),
		"secret":  secret,
		"note":    "Store this secret now. It is not shown again.",
	})
}

// UpdateWebhook handles POST /admin/webhooks/{id}. It never changes the secret.
func (h *Handler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	st := h.repo.WebhookStore()
	before, err := st.GetSubscription(r.Context(), id)
	if err != nil {
		webhookError(w, r, http.StatusNotFound, "webhook not found")
		return
	}
	in, err := webhookInputFromRequest(w, r)
	if err != nil {
		webhookError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if err := st.UpdateSubscription(r.Context(), id, in); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, pgx.ErrNoRows) {
			code = http.StatusNotFound
		}
		webhookError(w, r, code, err.Error())
		return
	}
	h.auditWebhook(r, "WEBHOOK_UPDATE", id, map[string]any{
		"name": in.Name, "url": in.URL, "event_types": in.EventTypes, "tag_scope": in.TagScope, "enabled": in.Enabled,
	})
	if before.AllowPrivateNetwork != in.AllowPrivateNetwork {
		h.auditWebhook(r, "WEBHOOK_ALLOW_PRIVATE_NETWORK", id, map[string]any{"name": in.Name, "allow": in.AllowPrivateNetwork})
	}
	if wantsHTML(r) {
		http.Redirect(w, r, "/admin/webhooks?msg=Webhook+updated", http.StatusSeeOther)
		return
	}
	updated, _ := st.GetSubscription(r.Context(), id)
	if updated == nil {
		writeWebhookJSON(w, http.StatusOK, map[string]any{"id": id})
		return
	}
	writeWebhookJSON(w, http.StatusOK, map[string]any{"webhook": toWebhookJSON(*updated)})
}

// RotateWebhookSecret handles POST /admin/webhooks/{id}/rotate and shows the new secret once.
func (h *Handler) RotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	st := h.repo.WebhookStore()
	sub, err := st.GetSubscription(r.Context(), id)
	if err != nil {
		webhookError(w, r, http.StatusNotFound, "webhook not found")
		return
	}
	secret, err := st.RotateSecret(r.Context(), id)
	if err != nil {
		log.Printf("[web] rotate webhook secret %s: %v", id, err)
		webhookError(w, r, http.StatusInternalServerError, "failed to rotate secret")
		return
	}
	h.auditWebhook(r, "WEBHOOK_ROTATE_SECRET", id, map[string]any{"name": sub.Name})
	if wantsHTML(r) {
		subs, _ := st.ListSubscriptions(r.Context())
		h.renderWebhooksPage(w, r, subs, &webhookFlashSecret{SubscriptionName: sub.Name, Secret: secret, Rotated: true})
		return
	}
	writeWebhookJSON(w, http.StatusOK, map[string]any{
		"id": id, "secret": secret, "note": "Store this secret now. It is not shown again.",
	})
}

// DeleteWebhook handles POST /admin/webhooks/{id}/delete and DELETE /admin/webhooks/{id}.
func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	st := h.repo.WebhookStore()
	sub, err := st.GetSubscription(r.Context(), id)
	if err != nil {
		webhookError(w, r, http.StatusNotFound, "webhook not found")
		return
	}
	if err := st.DeleteSubscription(r.Context(), id); err != nil {
		webhookError(w, r, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	h.auditWebhook(r, "WEBHOOK_DELETE", id, map[string]any{"name": sub.Name})
	if wantsHTML(r) {
		http.Redirect(w, r, "/admin/webhooks?msg=Webhook+deleted", http.StatusSeeOther)
		return
	}
	writeWebhookJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// TestWebhook handles POST /admin/webhooks/{id}/test: queues a webhook.test event.
func (h *Handler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	did, err := h.repo.WebhookStore().EnqueueTest(r.Context(), id, AdminUserFromContext(r.Context()))
	if err != nil {
		webhookError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	h.auditWebhook(r, "WEBHOOK_TEST", id, map[string]any{"delivery_id": did})
	if wantsHTML(r) {
		http.Redirect(w, r, "/admin/webhooks?sub="+id+"&msg=Test+event+queued", http.StatusSeeOther)
		return
	}
	writeWebhookJSON(w, http.StatusAccepted, map[string]any{"delivery_id": did})
}

// WebhookDeliveries handles GET /admin/webhooks/{id}/deliveries (JSON, with attempt logs).
func (h *Handler) WebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	st := h.repo.WebhookStore()
	if _, err := st.GetSubscription(r.Context(), id); err != nil {
		webhookError(w, r, http.StatusNotFound, "webhook not found")
		return
	}
	rows, err := st.ListDeliveries(r.Context(), id, 50)
	if err != nil {
		webhookError(w, r, http.StatusInternalServerError, "failed to load deliveries")
		return
	}
	out := make([]webhookDeliveryJSON, 0, len(rows))
	for _, d := range rows {
		dj := deliveryToJSON(d)
		if atts, err := st.ListAttempts(r.Context(), d.ID); err == nil {
			dj.AttemptLog = attemptsToJSON(atts)
		}
		out = append(out, dj)
	}
	writeWebhookJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

// RedeliverWebhook handles POST /admin/webhooks/deliveries/{did}/redeliver.
func (h *Handler) RedeliverWebhook(w http.ResponseWriter, r *http.Request) {
	did := chi.URLParam(r, "did")
	st := h.repo.WebhookStore()
	subID, err := st.DeliverySubscription(r.Context(), did)
	if err != nil {
		webhookError(w, r, http.StatusNotFound, "delivery not found")
		return
	}
	newID, err := st.Redeliver(r.Context(), did)
	if err != nil {
		webhookError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	h.auditWebhook(r, "WEBHOOK_REDELIVER", subID, map[string]any{"delivery_id": did, "new_delivery_id": newID})
	if wantsHTML(r) {
		http.Redirect(w, r, "/admin/webhooks?sub="+subID+"&msg=Redelivery+queued", http.StatusSeeOther)
		return
	}
	writeWebhookJSON(w, http.StatusAccepted, map[string]any{"delivery_id": newID})
}
