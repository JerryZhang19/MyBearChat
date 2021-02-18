package main

import (
	"log"
	_ "log"
	"net/http"
	_ "net/http"

	"github.com/BearCloud/fa20-project-dev/backend/friends/api"
	"github.com/gorilla/mux"
)

func main() {

	// Create a new mux for routing api calls
	router := mux.NewRouter()
	router.Use(CORS)
	
	err := api.RegisterRoutes(router)
	if err != nil {
		log.Fatal("Error registering API endpoints")
	}

	log.Print("friends service is up")
	http.ListenAndServe(":80", router)
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Set headers
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "http://http://ec2-3-14-81-168.us-east-2.compute.amazonaws.com:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Next
		next.ServeHTTP(w, r)
		return
	})
}