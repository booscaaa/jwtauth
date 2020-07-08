package factory

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

func GetConnection() *sql.DB {
	DBHost := os.Getenv("DB_HOST")
	DBUser := os.Getenv("DB_USER")
	DBPassword := os.Getenv("DB_PASSWORD")
	DBName := os.Getenv("DB_NAME")

	dbinfo := fmt.Sprintf("host=%s user=%s password=%s dbname=%s",
		DBHost, DBUser, DBPassword, DBName)

	db, err := sql.Open("postgres", dbinfo)
	checkErr(err)
	return db
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
