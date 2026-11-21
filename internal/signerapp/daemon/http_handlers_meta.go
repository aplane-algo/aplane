// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import "net/http"

func (fs *Signer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, fs.restService().Health(fs.productRuntime()))
}

func (fs *Signer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndRuntime(fs, w, r, http.MethodGet)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, fs.restService().Status(ir))
}

func (fs *Signer) handleKeys(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndRuntime(fs, w, r, http.MethodGet)
	if !ok {
		return
	}
	result, err := fs.restService().Keys(ir)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (fs *Signer) handleKeyTypes(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndRuntime(fs, w, r, http.MethodGet)
	if !ok {
		return
	}
	result, err := fs.restService().KeyTypes(ir)
	if err != nil {
		writeServiceErrorJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
