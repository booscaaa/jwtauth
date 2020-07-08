package provider

import (
	"api/controller/session"

	"github.com/gorilla/mux"
)

func Routes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/session", session.Create).Methods("POST", "OPTIONS")
	r.HandleFunc("/session", session.Refresh).Methods("GET", "OPTIONS")

	return r
}
