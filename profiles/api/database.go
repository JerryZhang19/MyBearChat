package api

import (
	"database/sql"
	"log"

	//MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB() *sql.DB {
	log.Println("attempting connections")
	var err error
	DB, err = sql.Open("mysql", "root:root@tcp(172.28.1.2:3306)/profiles")

	if err != nil {
		panic(err.Error())
	}

	return DB
}
