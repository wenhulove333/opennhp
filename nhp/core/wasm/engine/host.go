// Package engine provides host functions that can be called from within a WebAssembly (WASM) virtual machine.
// These functions enable interaction between the WASM runtime and the host environment,
// such as logging operations or other system-level interactions.

package engine

import (
	"encoding/binary"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"os"

	"github.com/tetratelabs/wazero/api"
)

var (
	confidentialContainerEvidenceUrl = "http://127.0.0.1:8006/aa/evidence?runtime_data=dhp"
)

func logString(_ context.Context, m api.Module, offset, byteCount uint32) {
	buf, ok := m.Memory().Read(offset, byteCount)
	if !ok {
		log.Panicf("Memory.Read(%d, %d) out of range", offset, byteCount)
	}
	fmt.Println(string(buf))
}

// Helper function to convert []interface{} to []byte
func interfaceToByteSlice(val any) ([]byte, error) {
    arr, ok := val.([]any)
    if !ok {
        return nil, fmt.Errorf("value is not a slice")
    }

    result := make([]byte, len(arr))
    for i, v := range arr {
        num, ok := v.(float64)
        if !ok {
            return nil, fmt.Errorf("element at index %d is not a number", i)
        }
        result[i] = byte(num)
    }
    return result, nil
}

func performXORBy4BytesGroup(data []byte, anouce uint32) []byte {
	result := make([]byte, 0, len(data))

	// Iterate through data in 4-byte steps
	for i := 0; i < len(data); i += 4 {
		// Create a 4-byte buffer
		var group [4]byte

		// Copy up to 4 bytes (handles partial last group)
		copy(group[:], data[i:min(i+4, len(data))])

		// Convert 4-byte group to int32 (using little-endian byte order)
		groupInt := binary.LittleEndian.Uint32(group[:])

		// Perform XOR with the key
		processedInt := uint32(uint32(groupInt) ^ anouce)

		// Convert back to bytes
		var processedGroup [4]byte
		binary.LittleEndian.PutUint32(processedGroup[:], processedInt)

		// Add to result, truncating if it's the last partial group
		end := i + 4
		if end > len(data) {
			end = len(data)
			result = append(result, processedGroup[:end-i]...)
		} else {
			result = append(result, processedGroup[:]...)
		}
	}

	return result
}

func GetEvidenceWithCCUrl() (map[string]any, error) {
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(confidentialContainerEvidenceUrl)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var evidence map[string]any

	if err := json.Unmarshal(buf, &evidence); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	// Extract attestation_report
	attReport, ok := evidence["attestation_report"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("attestation_report field is missing or invalid")
	}

	// Extract anonce
	anonce, ok := attReport["anonce"]
	if !ok {
		return nil, fmt.Errorf("anonce field is missing or invalid")
	}

	anonceUint32 := uint32(anonce.(float64))

	// Extract body
	body, ok := attReport["body"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("body field is missing or invalid")
	}

	// Extract measure
	measure, ok := body["measure"]
	if !ok {
		return nil, fmt.Errorf("measure field is missing")
	}

	// Extract serial_number
	sn, ok := evidence["serial_number"]
	if !ok {
		return nil, fmt.Errorf("serial_number field is missing")
	}

	measureBytes, err := interfaceToByteSlice(measure)
	if err != nil {
		return nil, fmt.Errorf("failed to convert measure to byte slice: %v", err)
	}

	restoredMeastureBytes := performXORBy4BytesGroup(measureBytes, anonceUint32)

	snBytes, err := interfaceToByteSlice(sn)
	if err != nil {
		return nil, fmt.Errorf("failed to convert serial number to byte slice: %v", err)
	}

	return map[string]any{
		"measure": hex.EncodeToString(restoredMeastureBytes),
		// "measure": string(bytes.TrimRight(snBytes, "\x00")),
		"serial number": string(bytes.TrimRight(snBytes, "\x00")),
	}, nil
}

func GetEvidenceWithAgentUuid() (map[string]any, error) {
	agentUniqueId, err := CalculateAgentUniqueId()
	if err != nil {
		return nil, fmt.Errorf("failed to get agent unique id: %v", err)
	}

	return map[string]any {
		"measure": string(agentUniqueId),
		"serial number": string(agentUniqueId),
	}, nil
}

func GetEvidence() (map[string]any, error) {
	evidence, err := GetEvidenceWithCCUrl()
	if err != nil {
		evidence, err = GetEvidenceWithAgentUuid()
		if err != nil {
			return nil, fmt.Errorf("failed to get evidence from CC or agent uuid")
		}
	}

	return evidence, nil
}

func CalculateAgentUniqueId() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	combined := hostname + string(cgroup)
	sum := sha256.Sum256([]byte(combined))

	return hex.EncodeToString(sum[:]), nil
}
