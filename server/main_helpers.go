package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/stelgen/reverseray/server/internal/tlscert"
)

func cryptoRead(b []byte) (int, error) {
	return rand.Read(b)
}

func healthzHTTP(url string) error {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	return nil
}

func caPinFromPEM(b []byte) string {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	_ = crypto.SHA256
	return tlscert.SPKIPin(cert)
}
