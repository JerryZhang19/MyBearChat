package api

import (
	"net/http"
	"github.com/gorilla/mux"
	"log"
	"bytes"
	"encoding/json"
	"fmt"
)

const NeptuneURL = "https://<your_neptune_writer_endpoint>:8182/gremlin"

func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/friends/{uuid}", areFriends).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/api/friends/{uuid}", addFriend).Methods(http.MethodPost, http.MethodOptions)
	// router.HandleFunc("/api/friends/{uuid}", deleteFriend).Methods(http.MethodDelete)
	// router.HandleFunc("/api/friends/{uuid}/mutual", mutualFriends).Methods(http.MethodGet)
	router.HandleFunc("/api/friends", getFriends).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/api/friends", addUser).Methods(http.MethodPost, http.MethodOptions)

	return nil
}

func getUUID (w http.ResponseWriter, r *http.Request) (uuid string) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err.Error())
	}
	//validate the cookie
	claims, err := ValidateToken(cookie.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}
	log.Println(claims)

	

	return claims["UserID"].(string)
}

func getFriends (w http.ResponseWriter, r *http.Request) {
	uuid := getUUID(w, r)
	gq := "g.V().has('uuid', '" + uuid + "').out('friends with').values('uuid')"
	response, err := makeNeptuneRequest(gq)
	// var req_body map[string]string
	// req_body["gremlin"] = "g.V().has('uuid', '" + uuid + "').out('friends with').values('uuid')"

	// jsonValue, _ := json.Marshal(req_body)

	// resp, err := http.Post(NeptuneURL, "application/json", bytes.NewBuffer(jsonValue))
	// defer resp.Body.Close()

	// var response map[string]interface{}
	
	// err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := response["result"].(map[string]interface{})
	data := result["data"].(map[string]interface{})
	values := data["@value"].([]interface{})

	json.NewEncoder(w).Encode(values)
	return
}

func areFriends(w http.ResponseWriter, r *http.Request) {
	otherUUID := mux.Vars(r)["uuid"]
	uuid := getUUID(w, r)
	gq := "g.V().has('uuid', '" + uuid + "').outE('friends with').where(otherV().has('uuid', '" + otherUUID + "')).count()"
	response, err := makeNeptuneRequest(gq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := response["result"].(map[string]interface{})
	data := result["data"].(map[string]interface{})
	values := data["@value"].([]interface{})
	value := values[0].(map[string]interface{})
	edges := value["@value"].(float64)

	if edges < 1 {
		fmt.Fprint(w, false)
	} else {
		fmt.Fprint(w, true)
	}

	return

}

func addFriend(w http.ResponseWriter, r *http.Request) {
	otherUUID := mux.Vars(r)["uuid"]
	uuid := getUUID(w, r)
	gq := "g.addE('friends with').from(g.V().has('uuid', '" + uuid + "')).to(g.V().has('uuid', '" + otherUUID + "'))"
	_, err := makeNeptuneRequest(gq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gq = "g.addE('friends with').from(g.V().has('uuid', '" + otherUUID + "')).to(g.V().has('uuid', '" + uuid + "'))"
	_, err = makeNeptuneRequest(gq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func addUser (w http.ResponseWriter, r *http.Request) {
	uuid := getUUID(w, r)
	gq := "g.addV().property('uuid', '" + uuid + "')"
	_, err := makeNeptuneRequest(gq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	return
}

// func deleteFriend(w http.ResponseWriter, r *http.Request) {
// 	otherUUID := mux.Vars(r)["uuid"]
// 	uuid := getUUID(w, r)
//   _, err := gremlinClient.Execute("g.V().bothE().filter(hasLabel('friends with')).where(inV().has('uuid', '" + uuid + "')).where(otherV().has('uuid', '" + otherUUID + "')).drop()")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		log.Print(err.Error())
// 		return
// 	}
// }

// func mutualFriends(w http.ResponseWriter, r *http.Request) {
// 	otherUUID := mux.Vars(r)["uuid"]
// 	uuid := getUUID(w, r)
// 	isFriend, err := gremlinClient.Execute("g.V().has('uuid', '" + uuid + "').both('friends with').and(both('friends with').has('uuid', '" +  otherUUID + "'))")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		log.Print(err.Error())
// 		return
// 	}
// 	json.NewEncoder(w).Encode(isFriend[0].Result.Data)
// }

func makeNeptuneRequest(gremlinQuery string) (map[string]interface{}, error) {
	req_body := make(map[string]string)
	req_body["gremlin"] = gremlinQuery
	jsonValue, _ := json.Marshal(req_body)
	resp, err := http.Post(NeptuneURL, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	response := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}
	return response, nil
}
