package api

import (
	"encoding/json"
	"net/http"

	"github.com/tarazel/beacon-gateway/internal/auth"
	"github.com/tarazel/beacon-gateway/internal/notifrules"
)

// GetNotificationRules returns the caller's own notification rules (the allow-all
// default when they've never set any). Rules are per-user, so no scope check is
// needed beyond authentication.
func (h *Handlers) GetNotificationRules(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	rule, err := h.notifrules.Get(r.Context(), userID)
	if err != nil {
		h.log.Error("notification rules: get failed", "user_id", userID, "err", err)
		writeError(w, http.StatusInternalServerError, "could not load rules")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// PutNotificationRules replaces the caller's notification rules. The store
// normalizes/clamps the input (trims/dedupes labels+zones, clamps min_score to
// [0,1] and quiet-hours minutes), so it echoes back the stored result.
func (h *Handlers) PutNotificationRules(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var rule notifrules.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.notifrules.Set(r.Context(), userID, rule); err != nil {
		h.log.Error("notification rules: set failed", "user_id", userID, "err", err)
		writeError(w, http.StatusInternalServerError, "could not save rules")
		return
	}
	saved, err := h.notifrules.Get(r.Context(), userID)
	if err != nil {
		h.log.Error("notification rules: reload failed", "user_id", userID, "err", err)
		writeError(w, http.StatusInternalServerError, "saved but could not reload rules")
		return
	}
	writeJSON(w, http.StatusOK, saved)
}
