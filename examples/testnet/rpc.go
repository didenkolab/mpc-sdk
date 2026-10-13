package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

const maxResponse = 8 << 20

// httpDo sends a request and returns the response body, failing on non-2xx.
func httpDo(method, url, contentType string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, url, resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func getJSON(url string, out any) error {
	body, err := httpDo(http.MethodGet, url, "", nil)
	if err != nil {
		return err
	}
	return decode(url, body, out)
}

func getText(url string) (string, error) {
	body, err := httpDo(http.MethodGet, url, "", nil)
	return strings.TrimSpace(string(body)), err
}

func postJSON(url string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	body, err := httpDo(http.MethodPost, url, "application/json", payload)
	if err != nil {
		return err
	}
	return decode(url, body, out)
}

func decode(url string, body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: decode response: %w", url, err)
	}
	return nil
}

// rpcError is a JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	if len(e.Data) > 0 && string(e.Data) != "null" {
		return fmt.Sprintf("rpc error %d: %s (%s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// jsonRPC calls a JSON-RPC 2.0 method and decodes its result into out.
func jsonRPC(url, method string, params, out any) error {
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
	if err := postJSON(url, req, &resp); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%s: %w", method, resp.Error)
	}
	if len(resp.Result) == 0 {
		return fmt.Errorf("%s: empty result", method)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("%s: decode result: %w", method, err)
	}
	return nil
}

// isRPCError reports whether err wraps a JSON-RPC error.
func isRPCError(err error) bool {
	var re *rpcError
	return errors.As(err, &re)
}
