package main

import (
	"fmt"
	"log"
	"net/http"

	"postit/db"
	"postit/router"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: Could not load .env file")
	}
	db.Dbconnect()

	r := router.Router()
	fmt.Println("the db started")
	fmt.Println("the server is getting started")
	fmt.Println("listening at port 8000")
	log.Fatal(http.ListenAndServe(":8000", r))

}
