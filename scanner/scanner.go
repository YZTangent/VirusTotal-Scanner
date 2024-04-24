package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

func SendFileToScan(file multipart.File, header *multipart.FileHeader, apiKey string) (string, error) {
	body := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(body)

	// add a form file to the body
	fileWriter, err := bodyWriter.CreateFormFile("fileUpload", header.Filename)
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

	// Read response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse JSON response
	var response map[string]interface{}
	err = json.Unmarshal(responseBody, &response)
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

func GetReport(id, apiKey string) ([]byte, error) {
	return nil, nil
}
