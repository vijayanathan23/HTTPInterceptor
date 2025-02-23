package handlers

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	//"time"
)

func HandleHTTP(w http.ResponseWriter, r *http.Request, interceptedData *[]map[string]string, mu *sync.Mutex) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	// Bypass Firefox captive portal detection
	if r.URL.Host == "detectportal.firefox.com" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	requestData := map[string]string{
		"method": r.Method,
		"url":    r.URL.String(),
		"body":   string(body),
	}

	// Create a new request instead of using the original one
	req, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	req.Header = r.Header.Clone()

	// Perform the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body once and create two copies
	originalRespBody, _ := io.ReadAll(resp.Body)
	respBodyForBrowser := make([]byte, len(originalRespBody))
	copy(respBodyForBrowser, originalRespBody)

	// Handle gzip decompression if needed
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(bytes.NewReader(originalRespBody))
		if err != nil {
			http.Error(w, "Failed to decompress response", http.StatusInternalServerError)
			return
		}
		defer gzipReader.Close()
		originalRespBody, _ = io.ReadAll(gzipReader)
	}

	contentType := resp.Header.Get("Content-Type")
	fmt.Println(requestData["url"])
	fmt.Println(contentType)

	// Log full HTTP response for debugging (without modifying resp.Body)
	dump, _ := httputil.DumpResponse(resp, false)
	requestData["response"] = html.EscapeString(string(originalRespBody))
	requestData["headers"] = string(dump)

	mu.Lock()
	*interceptedData = append(*interceptedData, requestData)
	mu.Unlock()

	// Copy response headers and status code
	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBodyForBrowser) // Send unmodified response to the browser
}

func HandleConnect(w http.ResponseWriter, r *http.Request) {
	// Establish connection to the target server
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to connect to target", http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Hijacking failed", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Confirm the connection to the client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay data between client and server
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

// DataHandler sends intercepted data as JSON
func DataHandler(w http.ResponseWriter, r *http.Request, interceptedData *[]map[string]string, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(*interceptedData)
}
