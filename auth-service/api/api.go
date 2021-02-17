package api

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	verifyTokenSize = 6
	resetTokenSize  = 6
)

// RegisterRoutes initializes the api endpoints and maps the requests to specific functions
func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/auth/signup", signup).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/signin", signin).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/logout", logout).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/verify", verify).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/sendreset", sendReset).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/auth/resetpw", resetPassword).Methods(http.MethodPost, http.MethodOptions)

	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		return err
	}

	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)
	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {

	if (*r).Method == "OPTIONS" {
		return
	}

	//Obtain the credentials from the request body
	cred := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&cred)
	if logErr(err,w,"error decoding request body") {return}

	//Check if the username already exists
	var exists bool
	err = DB.QueryRow("SELECT EXISTS (SELECT * FROM users WHERE username = ?)", cred.Username).Scan(&exists)
	if logErr(err,w,"error checking if user name exists") {return}

	if exists == true {
		http.Error(w, errors.New("this username is taken").Error(), http.StatusConflict)
		return
	}

	//Check if the email already exists
	err = DB.QueryRow("SELECT EXISTS (SELECT * FROM users WHERE email = ?)", cred.Email).Scan(&exists)
	if logErr(err,w,"error checking if email is taken") {return}
	if(exists==true){
		http.Error(w, errors.New("this email is taken").Error(), http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cred.Password), bcrypt.DefaultCost)
	if logErr(err,w,"error generating encrypted password") {return}

	userUuid := uuid.NewString()

	verificationToken := GetRandomBase62(verifyTokenSize)

	//Store credentials in database
	_, err = DB.Query("INSERT INTO users VALUES(?,?,?,?,?,?,?)", cred.Username, cred.Email, hashedPassword, false, "", verificationToken, userUuid)
	if logErr(err,w,"error inserting new user") {return}

	//Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userUuid,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	if logErr(err,w,"error generating access token") {return}

	//Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		// Leave these next three values commented for now
		// Secure: true,
		// HttpOnly: true,
		// SameSite: http.SameSiteNoneMode,
		Path: "/",
	})

	//Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userUuid,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	if logErr(err,w,"error generating refresh token") {return}

	//set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})

	// Send verification email
	err = SendEmail(cred.Email, "Email Verification", "user-signup.html", map[string]interface{}{"Token": verificationToken})
	if logErr(err,w,"error sending verification email") {return}

	w.WriteHeader(http.StatusCreated)
	return
}

func signin(w http.ResponseWriter, r *http.Request) {

	if (*r).Method == "OPTIONS" {
		return
	}

	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, errors.New("error creating refreshToken").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// obtain hashed password and username
	var exists bool
	err = DB.QueryRow("SELECT EXISTS(SELECT * from users WHERE username = ?)", credentials.Username).Scan(&exists)
	if logErr(err,w,"error checking username exists") {return}
	if exists != true{
		http.Error(w,errors.New("the username does not exist").Error(), http.StatusBadRequest)
		return
	}
	var hashedPassword, userID string
	err = DB.QueryRow("SELECT hashedPassword, userID FROM users WHERE username = ?", credentials.Username).Scan(&hashedPassword, &userID)
	if logErr(err,w,"error obtaining password of user") {return}

	// Check if hashed password matches the one corresponding to the email
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
	if logErr(err,w,"error generating encrypted password") {return}


	//Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	if logErr(err,w,"error generating access token") {return}

	//Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		// Leave these next three values commented for now
		// Secure: true,
		// HttpOnly: true,
		// SameSite: http.SameSiteNoneMode,
		Path: "/",
	})

	//Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})
	if logErr(err,w,"error creating refresh token") {return}

	//set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})

	w.WriteHeader(http.StatusOK)
	return
}

func logout(w http.ResponseWriter, r *http.Request) {

	if (*r).Method == "OPTIONS" {
		return
	}

	// logging out causes expiration time of cookie to be set to now

	//Set the access_token and refresh_token to have an empty value and set their expiration date to anytime in the past
	var expiresAt = time.Now()
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Expires: expiresAt,Path:"/"})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Expires: expiresAt,Path:"/"})

	// TODO write anything to response?
	w.WriteHeader(http.StatusOK)
	return
}

func verify(w http.ResponseWriter, r *http.Request) {

	if (*r).Method == "OPTIONS" {
		return
	}

	// token is a list of strings! because .Query() returns map[string][]string
	token, ok := r.URL.Query()["token"]
	// check that valid token exists
	if !ok || len(token[0]) < 1 {
		http.Error(w, errors.New("Url Param 'token' is missing").Error(), http.StatusInternalServerError)
		log.Print(errors.New("Url Param 'token' is missing").Error())
		return
	}


	// check whether this token is valid
	var exists_token bool;
	err := DB.QueryRow("SELECT EXISTS(SELECT * from users WHERE verifiedToken = ?)", token[0]).Scan(&exists_token)
	if logErr(err,w,"error checking verification token exists") {return}
	if exists_token != true{
		http.Error(w, errors.New("wrong token").Error(), http.StatusBadRequest)
		log.Print("wrong token received")
		return
	}

	//Obtain the user with the verifiedToken from the query parameter and set their verification status to the integer "1"
	_, err = DB.Exec("UPDATE users SET verified = 1, verifiedToken = '' WHERE verifiedToken = ?", token[0])
	if logErr(err,w,"error setting user verified") {return}
	w.WriteHeader(http.StatusOK)
	return
}

func sendReset(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}

	//Get the email from the body (decode into an instance of Credentials)
	cred := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		http.Error(w, errors.New("error decoding to get credential in handler sendReset").Error(), http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	//check for other miscallenous errors that may occur
	//what is considered an invalid input for an email?
	// TODO: add rules to check invalid email

	//generate reset token
	token := GetRandomBase62(resetTokenSize)

	//Obtain the user with the specified email and set their resetToken to the token we generated
	_, err = DB.Query("UPDATE users SET resetToken = ? WHERE email = ?", token, cred.Email)
	if logErr(err,w,"error setting reset token") {return}

	// Send verification email
	err = SendEmail(cred.Email, "BearChat Password Reset", "password-reset.html", map[string]interface{}{"Token": token})
	if logErr(err,w,"error sending verification email") {return}
	return
}

func resetPassword(w http.ResponseWriter, r *http.Request) {

	if (*r).Method == "OPTIONS" {
		return
	}

	//get token from query params
	token := r.URL.Query().Get("token")

	//get the username, email, and password from the body
	credentials := Credentials{}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if logErr(err,w,"error decoding body") {return}

	//Check for invalid inputs, return an error if input is invalid
	// TODO: How could it be?

	username := credentials.Username
	password := credentials.Password
	var exists bool
	//check if the username and token pair exist
	err = DB.QueryRow("SELECT EXISTS( SELECT * FROM users WHERE resetToken = ? AND username = ?)", token, username).Scan(&exists)
	if logErr(err,w,"error checking whether username and email exists") {
		return
	}

	//Check exists boolean. Call an error if the username-token pair doesn't exist
	if exists != true {
		http.Error(w, errors.New("Wrong Reset Token").Error(), http.StatusConflict)
		log.Print("wrong reset token")
		return
	}

	//Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if logErr(err,w,"error generating encrypted password") {return}

	//input new password and clear the reset token (set the token equal to empty string)
	_, err = DB.Exec("UPDATE users SET resetToken = ? , hashedPassword = ? WHERE username = ?", token, hashedPassword, username)
	if logErr(err,w,"error updating password") {return}

	//put the user in the redis cache to invalidate all current sessions (NOT IN SCOPE FOR PROJECT), leave this comment for future reference
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
