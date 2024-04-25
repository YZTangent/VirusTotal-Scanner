package db

import (
	"database/sql"
	rep "website/report"
)

func InsertReport(dbCon *sql.DB, report rep.ReportJson) error {
	_, err := dbCon.Exec("INSERT INTO reports (name, id) VALUES ($1, $2)",
		report.Name, report.Data.Id)
	if err != nil {
		return err
	}

	_, err = dbCon.Exec("INSERT INTO report_data (id, link_self, link_item, retrieved_at, malicious, suspicious, undetected, harmless, timeout, confirmed_timeout, failure, type_unsupported, sha256_hash, md5_hash, sha1_hash, size) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
		report.Data.Id, report.Data.Links.Self, report.Data.Links.Item, report.Data.Attributes.Date, report.Data.Attributes.Stats.Malicious, report.Data.Attributes.Stats.Suspicious, report.Data.Attributes.Stats.Undetected, report.Data.Attributes.Stats.Harmless, report.Data.Attributes.Stats.Timeout,
		report.Data.Attributes.Stats.ConfirmedTimeout, report.Data.Attributes.Stats.Failure, report.Data.Attributes.Stats.TypeUnsupported, report.Meta.FileInfo.Sha256, report.Meta.FileInfo.Md5, report.Meta.FileInfo.Sha1, report.Meta.FileInfo.Size)
	if err != nil {
		return err
	}

	for _, result := range report.Data.Attributes.Results {
		_, err := dbCon.Exec("INSERT INTO results (id, method, engine, version, engine_update, category, result) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			report.Data.Id, result.Method, result.EngineName, result.EngineVersion, result.EngineUpdate, result.Category, result.Result)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetReportById(dbCon *sql.DB, id string) (rep.ReportJson, error) {
	rows, err := dbCon.Query("SELECT * FROM report_data WHERE id = $1", id)
	if err != nil {
		return rep.ReportJson{}, err
	}
	defer rows.Close()

	var report rep.ReportJson
	for rows.Next() {
		report = rep.ReportJson{}
		err := rows.Scan(
			&report.Data.Id, &report.Data.Links.Self, &report.Data.Links.Item, &report.Data.Attributes.Date, &report.Meta.FileInfo.Sha256, &report.Meta.FileInfo.Md5, &report.Meta.FileInfo.Sha1, &report.Meta.FileInfo.Size, &report.Data.Attributes.Stats.Malicious, &report.Data.Attributes.Stats.Suspicious,
			&report.Data.Attributes.Stats.Undetected, &report.Data.Attributes.Stats.Harmless, &report.Data.Attributes.Stats.Timeout, &report.Data.Attributes.Stats.ConfirmedTimeout, &report.Data.Attributes.Stats.Failure, &report.Data.Attributes.Stats.TypeUnsupported)
		if err != nil {
			return rep.ReportJson{}, err
		}
	}

	return report, nil
}

func GetReports(dbCon *sql.DB) ([]rep.ReportNames, error) {
	rows, err := dbCon.Query("SELECT name, id FROM reports")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []rep.ReportNames
	for rows.Next() {
		report := rep.ReportNames{}
		err := rows.Scan(&report.Name, &report.Id)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}
