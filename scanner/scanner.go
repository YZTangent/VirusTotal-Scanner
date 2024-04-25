package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	rep "website/report"
)

func SendFileToScan(file multipart.File, header *multipart.FileHeader, apiKey string) (string, error) {
	body := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(body)

	// add a form file to the body
	fileWriter, err := bodyWriter.CreateFormFile("file", header.Filename)
	if err != nil {
		return "", err
	}
	// copy the file into the fileWriter
	_, err = io.Copy(fileWriter, file)
	if err != nil {
		return "", err
	}

	bodyWriter.Close()

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	response, err := parseResponse(resp)
	if err != nil {
		return "", err
	}

	// Extract the id field
	id, ok := response["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return "", fmt.Errorf("unable to extract id from response")
	}

	return id, nil
}

func GetReport(id, apiKey string) (rep.ReportJson, error) {
	report := rep.ReportJson{}

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", id), nil)
	if err != nil {
		return report, err
	}

	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return report, err
	}
	defer resp.Body.Close()
	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return report, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return report, err
	}

	// Parse JSON response
	var response rep.ReportJson
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return report, err
	}

	// Extract the id field
	data := response
	return data, nil
}

func parseResponse(resp *http.Response) (map[string]interface{}, error) {
	// Read response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var response map[string]interface{}
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}
