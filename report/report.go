package db

import "reflect"

type ReportJson struct {
	Name string
	Data struct {
		Id    string `json:"id"`
		Links struct {
			Self string `json:"self"`
			Item string `json:"item"`
		} `json:"links"`
		Attributes struct {
			Date  int `json:"date"`
			Stats struct {
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Undetected       int `json:"undetected"`
				Harmless         int `json:"harmless"`
				Timeout          int `json:"timeout"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure          int `json:"failure"`
				TypeUnsupported  int `json:"type-unsupported"`
			} `json:"stats"`
			Results map[string]struct {
				Method        string `json:"method"`
				EngineName    string `json:"engine_name"`
				EngineVersion string `json:"engine_version"`
				EngineUpdate  string `json:"engine_update"`
				Category      string `json:"category"`
				Result        string `json:"result"`
			} `json:"results"`
		}
	} `json:"data"`
	Meta struct {
		FileInfo struct {
			Sha256 string `json:"sha256"`
			Md5    string `json:"md5"`
			Sha1   string `json:"sha1"`
			Size   int    `json:"size"`
		} `json:"file_info"`
	} `json:"meta"`
}

type ReportNames struct {
	Name string
	Id   string
}

type Report struct {
	Name             string
	Id               string
	Self             string
	Date             int
	Malicious        int
	Suspicious       int
	Undetected       int
	Harmless         int
	Timeout          int
	ConfirmedTimeout int
	Failure          int
	TypeUnsupported  int
	Results          map[string]struct {
		Method        string
		EngineName    string
		EngineVersion string
		EngineUpdate  string
		Category      string
		Result        string
	}
	Sha256 string
	Md5    string
	Sha1   string
	Size   int
}

func ParseReport(json ReportJson) (Report, error) {
	report := Report{}

	// Get the type of the Response struct
	jsonType := reflect.TypeOf(json)

	// Iterate over the fields of ResponseJson
	for i := 0; i < jsonType.NumField(); i++ {
		field := jsonType.Field(i)
		fieldName := field.Name

		// Get the corresponding field value from ResponseJson
		fieldValue := reflect.ValueOf(json).FieldByName(fieldName)

		// Set the field value in Response
		reflect.ValueOf(&report).Elem().FieldByName(fieldName).Set(fieldValue)
	}

	return report, nil
}
