package main

import (
	"jwt-golang/autentication"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", autentication.Login)
	mux.HandleFunc("/validade", autentication.ValidateToken)
	log.Println("executando  em localHost:8080")

	http.ListenAndServe(":8080", mux)

}
