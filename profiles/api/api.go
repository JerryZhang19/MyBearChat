package api

import (
	"log"
	"net/http"
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/profile/{uuid}", getProfile).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/profile/{uuid}", updateProfile).Methods(/*YOUR CODE HERE*/)

	return nil
}

func getUUID (w http.ResponseWriter, r *http.Request) (uuid string) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, errors.New("error obtaining cookie: " + err.Error()).Error(), http.StatusBadRequest)
		log.Print(err.Error())
	}
	//validate the cookie
	claims, err := ValidateToken(cookie.Value)
	if err != nil {
		http.Error(w, errors.New("error validating token: " + err.Error()).Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}
	log.Println(claims)

	return claims["UserID"].(string)
}

func getProfile(w http.ResponseWriter, r *http.Request) {

	// Obtain the uuid from the url path and store it in a `uuid` variable
	// Hint: mux.Vars()
	// YOUR CODE HERE


	// Initialize a new Profile variable
	//YOUR CODE HERE


	// Obtain all the information associated with the requested uuid
	// Scan the information into the profile struct's variables
	// Remember to pass in the address!
	err := DB.QueryRow("YOUR CODE HERE", /* YOUR CODE HERE */).Scan(/* YOUR CODE HERE */, /* YOUR CODE HERE */, /* YOUR CODE HERE */, /* YOUR CODE HERE */)
	
	/*  Check for errors with querying the database
		Return an Internal Server Error if such an error occurs
	*/

  	//encode fetched data as json and serve to client
	json.NewEncoder(w).Encode(profile)
	return
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
	
	// Obtain the requested uuid from the url path and store it in a `uuid` variable
	// YOUR CODE HERE

	// Obtain the userID from the cookie
	// YOUR CODE HERE

	// If the two ID's don't match, return a StatusUnauthorized
	// YOUR CODE HERE

	// Decode the Request Body's JSON data into a profile variable

	// Return an InternalServerError if there is an error decoding the request body
	// YOUR CODE HERE


	// Insert the profile data into the users table
	// Check db-server/initdb.sql for the scheme
	// Make sure to use REPLACE INTO (as covered in the SQL homework)
	err = DB.Exec("YOUR CODE HERE", /* YOUR CODE HERE */, /* YOUR CODE HERE */, /* YOUR CODE HERE */, /* YOUR CODE HERE */)

	// Return an internal server error if any errors occur when querying the database.
	// YOUR CODE HERE

	return
}
