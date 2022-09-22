package main

import (
	"log"
	"net/http"
	"sso/authorizationserver"

	"github.com/rs/cors"
)
var corsHandler = cors.New(cors.Options{
	AllowedOrigins:   []string{"http://localhost:8080"},
	AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
	AllowedHeaders:   []string{"Origin", "Accept", "Content-Type", "X-Requested-With"},
	AllowCredentials: true,
	MaxAge:           0,
	Debug:            true,
})

var handler = corsHandler.Handler(authorizationserver.NewHttpHandler())

func main () {
	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		log.Fatal(err)
	}
}