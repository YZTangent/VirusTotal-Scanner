package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"website/scanner"
)

type Analysis struct {
	Name string
	Key  string
}

type Report struct {
	Name string
	Data struct {
		Id    string
		Links struct {
			Self string
			Item string
		}
	}
	Attributes struct {
		Date  string
		Stats struct {
			Malicious        int
			Suspicious       int
			Undetected       int
			Harmless         int
			Timeout          int
			ConfirmedTimeout int
			Failure          int
			TypeUnsupported  int
		}
	}
	Meta struct {
		FileInfo struct {
			sha256 string
			md5    string
			sha1   string
			size   int
		}
	}
}

var tmpl *template.Template
var apiKey string

func initPage() {
	apiKey = os.Getenv("VIRUSTOTAL_API_KEY")

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

	id, err := scanner.SendFileToScan(file, header, apiKey)
	if err != nil {
		log.Println("Error sending file to scan: ", err)
		http.Error(w, "Error sending file to scan", http.StatusInternalServerError)
	}
	log.Println("File sent to scan successfully: ", id)

	report, err := scanner.GetReport(id, apiKey)
	if err != nil {
		log.Println("Error retrieving report: ", err)
		http.Error(w, "Error retrieving report", http.StatusInternalServerError)
	}
	log.Println("Report retrieved successfully")

	var parsedReport Report
	parsedReport.Name = header.Filename
	err = json.Unmarshal(report, &parsedReport)
	if err != nil {
		log.Println("Error parsing report: ", err)
		http.Error(w, "Error parsing report", http.StatusInternalServerError)
	}
	log.Println("Report parsed successfully")
}

func main() {

	initPage()

	http.HandleFunc("/", loadPageHandler)

	http.HandleFunc("/submit", scanFileHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
