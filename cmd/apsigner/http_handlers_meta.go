// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "net/http"

func (fs *Signer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, fs.restService().Health(fs.productIdentityRuntime(), fs.sshServer != nil, fs.ipcServer != nil))
}

func (fs *Signer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ir, ok := requireMethodAndIdentity(fs, w, r, http.MethodGet, func(msg string) any { return errorResponse(msg) })
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, fs.restService().Status(ir))
}

func (fs *Signer) handleKeys(w http.ResponseWriter, r *http.Request) {
	ir, status, errMsg := fs.identityFromRequest(r)
	if errMsg != "" {
		writeErrorJSON(w, status, errMsg)
		return
	}

	result, err := fs.restService().Keys(ir)
	if err != nil {
		writeErrorJSON(w, err.HTTPStatus(), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (fs *Signer) handleKeyTypes(w http.ResponseWriter, r *http.Request) {
	ir, status, errMsg := fs.identityFromRequest(r)
	if errMsg != "" {
		writeErrorJSON(w, status, errMsg)
		return
	}

	result, err := fs.restService().KeyTypesForIdentity(ir)
	if err != nil {
		writeErrorJSON(w, err.HTTPStatus(), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
