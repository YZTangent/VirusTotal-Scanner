package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"website/db"
	rep "website/report"
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

	tmpl.Execute(w, map[string][]rep.ReportNames{"reports": reports})
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

	report.Name = header.Filename

	err = db.InsertReport(dbCon, report)
	if err != nil {
		log.Println("Error inserting report into database: ", err)
		http.Error(w, "Error inserting report into database", http.StatusInternalServerError)
		return
	}
	log.Println("Report inserted into database successfully")

	tmpl.ExecuteTemplate(w, "report-list-entry", rep.ReportNames{Name: report.Name, Id: report.Data.Id, IdTrunc: report.Data.Id[:6]})
}

func loadReportHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	log.Println("Loading report with id: ", id)

	report, err := db.GetReportById(dbCon, id)
	if err != nil {
		log.Println("Error retrieving report: ", err)
		http.Error(w, "Error retrieving report", http.StatusInternalServerError)
		return
	}

	log.Println("Report retrieved successfully")

	rep_tmpl := template.Must(template.ParseFiles("report.html"))
	rep_tmpl.Execute(w, report)
}

func main() {

	initPage()

	http.HandleFunc("/", loadPageHandler)

	http.HandleFunc("/submit", scanFileHandler)

	http.HandleFunc("/report", loadReportHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
