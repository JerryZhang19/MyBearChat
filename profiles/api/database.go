package api

import (
	"database/sql"
	"log"
	"time"

	//MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB() *sql.DB {
	log.Println("attempting connections")
	var err error
	DB, err = sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/profiles")

	_, err = DB.Query("SELECT * FROM users")
	for err != nil {
		log.Println("couldnt connect, waiting 20 seconds before retrying")
		time.Sleep(20*time.Second)
		_, err = DB.Query("SELECT * FROM users")
	}

	return DB
}
