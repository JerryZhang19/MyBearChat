package api

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/profile/{uuid}", getProfile).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/api/profile/{uuid}", updateProfile).Methods(http.MethodPut, http.MethodOptions)

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
	if (*r).Method == "OPTIONS" {
		return
	}

	// Obtain the uuid from the url path and store it in a `uuid` variable
	userUuid := mux.Vars(r)["uuid"]
	profile := Profile{}

	// Obtain all the information associated with the requested uuid
	// Scan the information into the profile struct's variables
	// Remember to pass in the address!
	err := DB.QueryRow("SELECT * FROM users WHERE uuid = ?", userUuid).Scan(&profile.Firstname,&profile.Lastname, &profile.Email, &profile.UUID)
	if logErr(err,w,"error getting profile") {return}
  	//encode fetched data as json and serve to client
	err = json.NewEncoder(w).Encode(profile)
	if logErr(err,w,"error decoding") {return}

	return
}

func updateProfile(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}

	userUuid := mux.Vars(r)["uuid"]
	userUuidCookie := getUUID(w,r)

	if userUuid != userUuidCookie{reportErr(w,http.StatusUnauthorized, "unauthorized"); return}

	profile := Profile{}
	err := json.NewDecoder(r.Body).Decode(&profile)
	if logErr(err,w,"error decoding body") {return}



	// Insert the profile data into the users table
	// Check db-server/initdb.sql for the scheme
	// Make sure to use REPLACE INTO (as covered in the SQL homework)
	_, err = DB.Exec("REPLACE INTO users VALUES (?,?,?,?)", profile.Firstname, profile.Lastname, profile.Email, profile.UUID)
	if logErr(err,w,"error updating profile") {return}

	return
}



func logErr(err error,w http.ResponseWriter, message string) bool {
	if err != nil {
		http.Error(w, message, http.StatusInternalServerError)
		log.Print(message)
		log.Print(err.Error())
	}
	return err != nil
}

func reportErr(w http.ResponseWriter, statusCode int, message string){
	http.Error(w, message, statusCode)
	log.Print(message)
}
