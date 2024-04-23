package main

import (
	"html/template"
	"log"
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

var tmpl *template.Template

func initPage() {
	tmpl = template.Must(template.ParseFiles("index.html"))
}

func loadPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.Execute(w, map[string][]Analysis{"Analysis": {{Name: "Analysis 1"}, {Name: "Analysis 2"}}})
}

func scanFileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received file submission")

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		log.Println("Error parsing form: ", err)
		http.Error(w, "Error parsing submission", http.StatusInternalServerError)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Println("Error retrieving file from form: ", err)
		http.Error(w, "Error retrieving file from form: ", http.StatusInternalServerError)
	}
	defer file.Close()

	log.Println("File received successfully: ", header.Filename)
}

func main() {

	initPage()

	http.HandleFunc("/", loadPageHandler)

	http.HandleFunc("/submit", scanFileHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
