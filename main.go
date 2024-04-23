package main

import (
	"html/template"
	"net/http"
)

type Analysis struct {
	Name string
	Key  string
}

type Reports struct {
	Name   string
	Report []byte
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, _ := template.ParseFiles("index.html")
		tmpl.Execute(w, map[string][]Analysis{"Analysis": {{Name: "Analysis 1"}, {Name: "Analysis 2"}}})
	})

	http.ListenAndServe(":8080", nil)
}
