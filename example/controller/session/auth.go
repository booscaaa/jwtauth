package session

import (
	"encoding/json"
	"net/http"

	"github.com/booscaaa/jwtauth"
)

//SetOrigins .
func SetOrigins(w http.ResponseWriter) http.ResponseWriter {
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, DELETE, PUT")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	return w
}

//Create .
func Create(w http.ResponseWriter, r *http.Request) {
	w = SetOrigins(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	} else {
		var access jwtauth.Access
		if err := json.NewDecoder(r.Body).Decode(&access); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 - Something bad happened!"))
		} else {
			defer r.Body.Close()
			jwtauth.SessionCreate(access, w)
		}
	}
}

//Refresh .
func Refresh(w http.ResponseWriter, r *http.Request) {
	w = SetOrigins(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	} else {
		bearToken := r.Header.Get("Authorization")
		jwtauth.SessionRefresh(bearToken, w)
	}
}
