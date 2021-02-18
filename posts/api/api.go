package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strconv"
	"time"
)


func RegisterRoutes(router *mux.Router) error {
	// Why don't we put options here? Check main.go :)

	router.HandleFunc("/api/posts/{startIndex}", getFeed).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/api/posts/{uuid}/{startIndex}", getPosts).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/api/posts/create", createPost).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/api/posts/delete/{postID}", deletePost).Methods(http.MethodDelete, http.MethodOptions)

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
		return ""
	}
	log.Println(claims)
	return claims["UserID"].(string)
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}

	// Load the uuid and startIndex from the url paramater into their own variables
	requestedUuid := mux.Vars(r)["uuid"]
	startIndex, err := strconv.Atoi(mux.Vars(r)["startIndex"])
	if err!=nil {reportErr(w,http.StatusBadRequest,"can't convert index to int"); return}

	// Check if the user is authorized
	// First get the uuid from the access_token (see getUUID())
	// Compare that to the uuid we got from the url parameters, if they're not the same, return an error http.StatusUnauthorized
	// YOUR CODE HERE
	userUuid := getUUID(w, r)
	if userUuid == "" {return}


	if userUuid != requestedUuid{
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Print("Unauthorized uuid don't match")
	}
	
	var posts *sql.Rows
	posts, err = DB.Query("SELECT * FROM posts WHERE authorID = ? ORDER BY postTime DESC LIMIT ?, 25", userUuid, startIndex)
	if logErr(err,w,"error taking posts from database") {return}

	var (
		content string
		postID string
		userID string
		postTime time.Time
	)
	numPosts := 0
	// Create "postsArray", which is a slice (array) of Posts. Make sure it has size 25
	// Hint: https://tour.golang.org/moretypes/13
	postsArray := make([]Post, 25)

	for i := 0; i < 25 && posts.Next(); i++ {
		// Every time we call posts.Next() we get access to the next row returned from our query
		// Question: How many columns did we return
		// Reminder: Scan() scans the rows in order of their columns. See the variables defined up above for your convenience
		err = posts.Scan(&content, &postID, &userID, &postTime)
		if logErr(err,w,"error scanning var posts to extract things") {return}
		postsArray[i] = Post{content, postID, userID, postTime, ""}
		numPosts++
	}

	posts.Close()
	err = posts.Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}
  json.NewEncoder(w).Encode(postsArray[0:numPosts])
  return
}

func createPost(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}
	// Obtain the userID from the JSON Web Token
	// See getUUID(...)
	userUuid := getUUID(w, r)
	if userUuid == "" {return}

	// Create a Post object and then Decode the JSON Body (which has the structure of a Post) into that object
	post := Post{}
	err := json.NewDecoder(r.Body).Decode(&post)

	postUuid := uuid.NewString()


	//Load our location in PST
	pst, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	currPST := time.Now().In(pst)

	// Insert the post into the database
	// Look at /db-server/initdb.sql for a better understanding of what you need to insert
	result , err := DB.Exec("INSERT INTO posts VALUES(?,?,?,?) ", post.PostBody, postUuid, userUuid, currPST)
	if logErr(err,w,"error inserting post into database") {return}
	// Check errors with executing the query
	// YOUR CODE HERE

	rowsAffected, err := result.RowsAffected()
	if logErr(err,w,"error counting rows affected") {return}
	if rowsAffected<1{
		http.Error(w, "no rows affected during insertion", http.StatusInternalServerError)
		log.Print("no rows affected during insertion")
	}

	w.WriteHeader(http.StatusCreated)
	return
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}

	postID := mux.Vars(r)["postID"]
	userUuid := getUUID(w,r)

	var exists bool
	//check if post exists
	err := DB.QueryRow("SELECT EXISTS(SELECT * FROM posts WHERE PostID = ?)", postID).Scan(&exists)
	if logErr(err,w,"err checking if post exists") {return}

	// Check if the post actually exists, otherwise return an http.StatusNotFound
	if exists != true{reportErr(w,http.StatusNotFound,"no post with requested postID"); return}

	// Get the authorID of the post with the specified postID
	var authorID string
	err = DB.QueryRow("SELECT authorID FROM posts WHERE postID = ?", postID).Scan(&authorID)
	if logErr(err,w,"err getting authorID") {return}

	// Check if the uuid from the access token is the same as the authorID from the query
	if userUuid != authorID {reportErr(w,http.StatusUnauthorized,"mismatched authorID");return}

	// Delete the post since by now we're authorized to do so
	_, err = DB.Exec("DELETE FROM posts WHERE postID= ?", postID)
	if logErr(err,w,"err deleting the post") {return}

	return
}

func getFeed(w http.ResponseWriter, r *http.Request) {
	if (*r).Method == "OPTIONS" {
		return
	}
	// get the start index from the url paramaters
	// based on the previous functions, you should be familiar with how to do so
	startIndex, err := strconv.Atoi(mux.Vars(r)["startIndex"])
	if err!=nil {reportErr(w,http.StatusBadRequest,"input index can't convert to int"); return}

	//userUuid := getUUID(w,r)
	getUUID(w,r)
	// Obtain all of the posts where the authorID is *NOT* the current authorID
	// Sort chronologically
	// Always limit to 25 queries
	// Always start at an offset of startIndex
	//posts, err := DB.Query("SELECT * FROM posts WHERE authorID != ? ORDER BY postTime DESC LIMIT ?, 25", userUuid, startIndex)
	posts, err := DB.Query("SELECT * FROM posts ORDER BY postTime DESC LIMIT ?, 25", startIndex)
	if logErr(err,w,"error taking posts from database") {return}

	var (
		content string
		postID string
		userID string
		postTime time.Time
	)
	numPosts := 0
	// Create "postsArray", which is a slice (array) of Posts. Make sure it has size 25
	// Hint: https://tour.golang.org/moretypes/13
	postsArray := make([]Post, 25)

	for i := 0; i < 25 && posts.Next(); i++ {
		// Every time we call posts.Next() we get access to the next row returned from our query
		// Question: How many columns did we return
		// Reminder: Scan() scans the rows in order of their columns. See the variables defined up above for your convenience
		err = posts.Scan(&content, &postID, &userID, &postTime)
		if logErr(err,w,"error scanning var posts to extract things") {return}
		postsArray[i] = Post{content, postID, userID, postTime, ""}
		numPosts++
	}

	posts.Close()
	err = posts.Err()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}
	json.NewEncoder(w).Encode(postsArray[0:numPosts])
	return

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


