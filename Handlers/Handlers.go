package handlers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"
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

func HandleConnect(w http.ResponseWriter, r *http.Request, interceptedData *[]map[string]string, mu *sync.Mutex) {
	// Connect to the real server
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "Failed to connect to target", http.StatusServiceUnavailable)
		fmt.Println("[ERROR] Failed to connect to target:", err)
		return
	}
	defer destConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		fmt.Println("[ERROR] Connection hijacking not supported")
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusServiceUnavailable)
		fmt.Println("[ERROR] Hijacking failed:", err)
		return
	}
	defer clientConn.Close()

	// Send HTTP 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Generate a signed MITM TLS certificate for the target host
	tlsCert, err := generateSignedCert(r.Host)
	if err != nil {
		fmt.Println("[ERROR] Failed to generate TLS certificate:", err)
		return
	}

	// Wrap client connection with TLS (MITM)
	clientTLSConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err := clientTLSConn.Handshake(); err != nil {
		fmt.Println("[ERROR] TLS handshake with client failed:", err)
		return
	}

	// Establish a TLS connection to the real server
	serverTLSConn := tls.Client(destConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := serverTLSConn.Handshake(); err != nil {
		fmt.Println("[ERROR] TLS handshake with real server failed:", err)
		return
	}

	// Read the request from the client
	clientRequest, err := http.ReadRequest(bufio.NewReader(clientTLSConn))
	if err != nil {
		fmt.Println("[ERROR] Failed to read client request:", err)
		return
	}

	// Capture request headers
	requestDump, err := httputil.DumpRequest(clientRequest, true)
	if err != nil {
		fmt.Println("[ERROR] Failed to dump client request:", err)
		return
	}

	// Forward request to real server
	clientRequest.Write(serverTLSConn)

	// Read the response from the server
	serverResponse, err := http.ReadResponse(bufio.NewReader(serverTLSConn), clientRequest)
	if err != nil {
		fmt.Println("[ERROR] Failed to read server response:", err)
		return
	}

	// **Clone the response using httputil.DumpResponse**
	responseDump, err := httputil.DumpResponse(serverResponse, true) // Full headers + body
	if err != nil {
		fmt.Println("[ERROR] Failed to dump server response:", err)
		return
	}

	// **Reconstruct the response for interception (cloned version)**
	clonedResponse, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseDump)), clientRequest)
	if err != nil {
		fmt.Println("[ERROR] Failed to reconstruct response:", err)
		return
	}

	// **Forward the original response to the browser (unmodified)**
	serverResponse.Write(clientTLSConn)

	// **Process cloned response for data storage**
	body, err := io.ReadAll(clonedResponse.Body)
	if err != nil {
		fmt.Println("[ERROR] Failed to read response body:", err)
		return
	}
	clonedResponse.Body.Close() // Close after reading

	// **Check if the response is compressed**
	contentEncoding := clonedResponse.Header.Get("Content-Encoding")
	if contentEncoding == "gzip" {
		body = decodeGzip(body) // Decode gzip properly
		fmt.Println("[INFO] Gzip response detected and decoded")
	}

	// Detect Content Type
	contentType := clonedResponse.Header.Get("Content-Type")

	// **Check if the response is binary**
	var responseBody string
	if isBinaryContent(contentType) {
		responseBody = base64.StdEncoding.EncodeToString(body) // Encode binary data
		fmt.Println("[INFO] Binary response detected, stored as Base64")
	} else {
		responseBody = html.EscapeString(string(body)) // Store decompressed text
	}

	// Store intercepted request & response with headers
	mu.Lock()
	*interceptedData = append(*interceptedData, map[string]string{
		"method":   clientRequest.Method,
		"url":      fmt.Sprintf("https://%s%s", r.Host, clientRequest.URL.String()),
		"headers":  string(responseDump), // Full response dump
		"request":  string(requestDump),
		"response": responseBody, // Stores decompressed text or base64 binary
	})
	mu.Unlock()
}

func decodeGzip(data []byte) []byte {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		fmt.Println("[WARN] Failed to decode gzip, returning raw data")
		return data // Return original if it's not gzip
	}
	defer reader.Close()

	decodedData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("[WARN] Failed to read decompressed gzip, returning raw data")
		return data
	}

	return decodedData
}

func isBinaryContent(contentType string) bool {
	binaryTypes := []string{"audio/", "video/", "image/", "application/octet-stream"}
	for _, prefix := range binaryTypes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func generateSignedCert(host string) (tls.Certificate, error) {
	// Remove port from host (e.g., "www.example.com:443" → "www.example.com")
	cleanHost, _, err := net.SplitHostPort(host)
	if err != nil {
		cleanHost = host // If no port is present, keep original host
	}

	// Load the root CA certificate
	rootCAData, err := os.ReadFile("rootCA.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read root CA certificate: %v", err)
	}

	// Load the root CA private key
	rootKeyData, err := os.ReadFile("rootCA_TSP.key")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read root CA key: %v", err)
	}

	// Parse root CA certificate
	rootBlock, _ := pem.Decode(rootCAData)
	if rootBlock == nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode root CA certificate")
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse root CA certificate: %v", err)
	}

	// Parse root CA private key (supporting both PKCS#1 & PKCS#8)
	keyBlock, _ := pem.Decode(rootKeyData)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode root CA key")
	}

	var rootKey *rsa.PrivateKey
	if parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		rootKey = parsedKey
	} else if parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		var ok bool
		rootKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("root CA key is not an RSA key")
		}
	} else {
		return tls.Certificate{}, fmt.Errorf("failed to parse root CA key: %v", err)
	}

	// Generate new RSA key for the MITM certificate
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key: %v", err)
	}

	// Create certificate template for the intercepted domain
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cleanHost, // Use cleaned hostname (without port)
			Organization: []string{"MITM Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),           // Valid 1 hour before to prevent clock skew issues
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cleanHost}, // Use cleaned hostname in SAN (Fixes Firefox errors)
	}

	// Sign the certificate with the root CA
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, &certKey.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to sign certificate: %v", err)
	}

	// Encode the new certificate & private key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})

	// Load and return the signed TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	return tlsCert, nil
}

// DataHandler sends intercepted data as JSON
func DataHandler(w http.ResponseWriter, r *http.Request, interceptedData *[]map[string]string, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(*interceptedData)
}
