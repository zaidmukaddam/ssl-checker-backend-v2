package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type CertificateInfo struct {
	Chain              []CertChain `json:"chain"`
	CommonName         string      `json:"commonName"`
	Organization       string      `json:"organization"`
	Location           string      `json:"location"`
	ValidFrom          string      `json:"validFrom"`
	ValidTo            string      `json:"validTo"`
	SerialNumber       string      `json:"serialNumber"`
	SignatureAlgorithm string      `json:"signatureAlgorithm"`
	Issuer             string      `json:"issuer"`
	IpAddress          string      `json:"ipAddress"`
}

type CertChain struct {
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	Location           string `json:"location"`
	ValidFrom          string `json:"validFrom"`
	ValidTo            string `json:"validTo"`
	SerialNumber       string `json:"serialNumber"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	Issuer             string `json:"issuer"`
}

func createCertificate(c *gin.Context) {
	// Get parameters from the query
	domain := c.DefaultQuery("domain", "example.com")
	orgName := c.DefaultQuery("org", "Example Organization")
	email := c.DefaultQuery("email", "admin@example.com")

	// Generate a new private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate private key."})
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{orgName},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: email,
				},
			},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create certificate."})
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to marshal private key."})
		return
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	c.JSON(200, gin.H{
		"certificate": string(certPEM),
		"private_key": string(privPEM),
	})
}

func getSSLInfo(c *gin.Context) {
	hostname := c.DefaultQuery("hostname", "")
	if hostname == "" {
		c.JSON(400, gin.H{"error": "Hostname is required."})
		return
	}

	ipAddress, err := net.LookupHost(hostname)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch IP Address."})
		return
	}

	// Configure tls to fetch certificate
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", hostname+":443", conf)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to connect: " + err.Error()})
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		c.JSON(500, gin.H{"error": "Failed to retrieve certificate details"})
		return
	}

	var chain []CertChain
	for _, cert := range certs {
		Location := ""
		if len(cert.Subject.Locality) > 0 {
			Location = cert.Subject.Locality[0]
		} else if len(cert.Subject.Province) > 0 {
			Location = cert.Subject.Province[0]
		} else if len(cert.Subject.Country) > 0 {
			Location = cert.Subject.Country[0]
		}
		Organization := ""
		if len(cert.Subject.Organization) > 0 {
			Organization = cert.Subject.Organization[0]
		} else if len(cert.Subject.OrganizationalUnit) > 0 {
			Organization = cert.Subject.OrganizationalUnit[0]
		}
		chain = append(chain, CertChain{
			CommonName:         cert.Subject.CommonName,
			Organization:       Organization,
			Location:           Location,
			ValidFrom:          cert.NotBefore.String(),
			ValidTo:            cert.NotAfter.String(),
			SerialNumber:       cert.SerialNumber.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			Issuer:             cert.Issuer.CommonName,
		})
	}

	firstCert := certs[0]
	CommonName := firstCert.Subject.CommonName
	Organization := ""
	if len(firstCert.Subject.Organization) > 0 {
		Organization = firstCert.Subject.Organization[0]
	} else if len(firstCert.Subject.OrganizationalUnit) > 0 {
		Organization = firstCert.Subject.OrganizationalUnit[0]
	}
	Location := ""
	if len(firstCert.Subject.Locality) > 0 {
		Location = firstCert.Subject.Locality[0]
	} else if len(firstCert.Subject.Province) > 0 {
		Location = firstCert.Subject.Province[0]
	} else if len(firstCert.Subject.Country) > 0 {
		Location = firstCert.Subject.Country[0]
	}

	certInfo := CertificateInfo{
		Chain:              chain,
		CommonName:         CommonName,
		Organization:       Organization,
		Location:           Location,
		ValidFrom:          firstCert.NotBefore.String(),
		ValidTo:            firstCert.NotAfter.String(),
		SerialNumber:       firstCert.SerialNumber.String(),
		SignatureAlgorithm: firstCert.SignatureAlgorithm.String(),
		Issuer:             firstCert.Issuer.CommonName,
		IpAddress:          ipAddress[0],
	}

	c.JSON(200, certInfo)
}

func main() {
	r := gin.Default()

	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true // Allow all origins. For more granular control, set specific origins.
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}
	r.Use(cors.New(config))

	r.Use(gin.Logger())   // Logging
	r.Use(gin.Recovery()) // Panic recovery

	r.GET("/sslinfo", getSSLInfo)
	r.POST("/createCert", createCertificate)  // This line has been modified

	r.Run()
}
