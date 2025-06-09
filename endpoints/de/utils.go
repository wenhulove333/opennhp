package de

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func ReadPolicyFile(filePath string) (common.SmartPolicy, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("error reading file: %v", err)
	}

	var config common.SmartPolicy

	err = json.Unmarshal(fileContentByte, &config)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("json parsing error: %s", err)
	}
	return config, nil
}
func SaveDataPrivateKeyBase64(doId string, dataPrivateKeyBase64 string) error {
	// Make sure the etc directory exists
	etcDir := "etc/ztdo"
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return fmt.Errorf("failed to create etc directory: %v", err)
	}

	// Check if etc/config.json already exists
	fileName := "data-" + doId + ".json"
	fullPath := filepath.Join(etcDir, fileName)
	if _, err := os.Stat(fullPath); err == nil {
		return fmt.Errorf("%v already exists, please delete it first", fullPath)
	}

	// Create etc/config.json file
	file, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create config.json: %v", err)
	}
	defer file.Close()

	file.Write([]byte(dataPrivateKeyBase64))

	return nil
}

func GetDataPrivateKeyBase64(doId string) (string, error) {
	etcDir := "etc/ztdo"
	fileName := "data-" + doId + ".json"

	fullPath := filepath.Join(etcDir, fileName)

	// open and read all the content in file
	file, err := os.Open(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to open config.json: %v", err)
	}

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	return string(fileContentByte), nil
}
