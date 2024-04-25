package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"website/db"
	"website/scanner"

	_ "github.com/lib/pq"
)

var tmpl *template.Template
var apiKey string
var dbCon *sql.DB

func initPage() {
	apiKey = os.Getenv("VIRUSTOTAL_API_KEY")
	dbUrl := os.Getenv("DB_URL")

	var err error
	dbCon, err = sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	fmt.Println("API Key: ", apiKey)
	tmpl = template.Must(template.ParseFiles("index.html"))
}

func loadPageHandler(w http.ResponseWriter, r *http.Request) {
	reports, err := db.GetReports(dbCon)
	if err != nil {
		log.Println("Error retrieving reports: ", err)
		http.Error(w, "Error retrieving reports", http.StatusInternalServerError)
	}

	tmpl.Execute(w, reports)
}

func scanFileHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received file submission")

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		log.Println("Error parsing form: ", err)
		http.Error(w, "Error parsing submission", http.StatusInternalServerError)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Println("Error retrieving file from form: ", err)
		http.Error(w, "Error retrieving file from form: ", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	log.Println("File received successfully: ", header.Filename)

	id, err := scanner.SendFileToScan(file, header, apiKey)
	if err != nil {
		log.Println("Error sending file to scan: ", err)
		http.Error(w, "Error sending file to scan", http.StatusInternalServerError)
		return
	}
	log.Println("File sent to scan successfully: ", id)

	log.Println(id)

	report, err := scanner.GetReport(id, apiKey)
	if err != nil {
		log.Println("Error retrieving report: ", err)
		http.Error(w, "Error retrieving report", http.StatusInternalServerError)
		return
	}
	log.Println("Report retrieved successfully")

	err = db.InsertReport(dbCon, report)
	if err != nil {
		log.Println("Error inserting report into database: ", err)
		http.Error(w, "Error inserting report into database", http.StatusInternalServerError)
		return
	}
	log.Println("Report inserted into database successfully")

	log.Printf("%v, %T\n", report, report)
	// var parsedReport Report
	// parsedReport.Name = header.Filename
	// err = json.Unmarshal(report, &parsedReport)
	// if err != nil {
	// 	log.Println("Error parsing report: ", err)
	// 	http.Error(w, "Error parsing report", http.StatusInternalServerError)
	// 	return
	// }
	// log.Println("Report parsed successfully")
}

func main() {

	initPage()

	http.HandleFunc("/", loadPageHandler)

	http.HandleFunc("/submit", scanFileHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
