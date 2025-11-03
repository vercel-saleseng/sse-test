package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"
)

//go:embed index.html
var indexHTML string

func main() {
	http.HandleFunc("GET /", serveHome)
	http.HandleFunc("GET /events", handleSSE)

	// Generate self-signed certificate in memory
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Create TLS config with the certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Create HTTPS server
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	port := ":443"
	log.Printf("Server starting on https://localhost%s", port)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// generateSelfSignedCert creates a self-signed TLS certificate in memory
func generateSelfSignedCert() (tls.Certificate, error) {
	log.Printf("Generating self-signed certificate in memory...")

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SSE Server"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Marshal private key
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Create tls.Certificate from PEM-encoded data
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	log.Printf("Self-signed certificate generated successfully")
	return tlsCert, nil
}

// serveHome serves the static HTML page
func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

// handleSSE handles Server-Sent Events
func handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	interval := time.Second
	payload := 0

	intervalStr := r.URL.Query().Get("interval")
	if intervalStr != "" {
		intervalInt, err := strconv.Atoi(intervalStr)
		if err != nil {
			http.Error(w, "Invalid interval", http.StatusBadRequest)
			return
		}
		interval = time.Duration(intervalInt) * time.Millisecond
	}

	payloadStr := r.URL.Query().Get("payload")
	if payloadStr != "" {
		var err error
		payload, err = strconv.Atoi(payloadStr)
		if err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
	}

	log.Printf("Starting request with interval %v and payload %d", interval, payload)

	// Channel to signal when client disconnects
	notify := r.Context().Done()

	messageID := 0
	sendMessage := func(t time.Time) {
		messageID++
		baseMessage := fmt.Sprintf("Message #%d at %s", messageID, t.Format("15:04:05.000"))

		// Get current payload payload
		var message string

		if payload > 0 {
			// Calculate how much padding we need
			baseLen := len(baseMessage)
			if payload > baseLen {
				// Add padding to reach desired size
				padding := make([]byte, payload-baseLen)
				for i := range padding {
					padding[i] = 'A' + byte(i%26) // Fill with A-Z pattern
				}
				message = baseMessage + " | " + string(padding)
			} else {
				message = baseMessage
			}
		} else {
			message = baseMessage
		}

		// Send the message in SSE format
		fmt.Fprintf(w, "data: %s\n\n", message)
		flusher.Flush()

		log.Printf("Sent: %s (size: %d bytes)", baseMessage, len(message))
	}
	sendMessage(time.Now())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Client connected to SSE stream")

	for {
		select {
		case <-notify:
			log.Printf("Client disconnected from SSE stream")
			return
		case t := <-ticker.C:
			sendMessage(t)
		}
	}
}
