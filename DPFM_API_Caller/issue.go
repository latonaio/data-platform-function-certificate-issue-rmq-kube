package dpfm_api_caller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	dpfm_api_input_reader "data-platform-function-certificate-issue-rmq-kube/DPFM_API_Input_Reader"
	dpfm_api_output_formatter "data-platform-function-certificate-issue-rmq-kube/DPFM_API_Output_Formatter"
	"data-platform-function-certificate-issue-rmq-kube/config"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	rabbitmq "github.com/latonaio/rabbitmq-golang-client-for-data-platform"
	"io/ioutil"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/latonaio/golang-logging-library-for-data-platform/logger"
)

func (c *DPFMAPICaller) process(
	ctx context.Context,
	mtx *sync.Mutex,
	input *dpfm_api_input_reader.SDC,
	output *dpfm_api_output_formatter.SDC,
	accepter []string,
	errs *[]error,
	log *logger.Logger,
	conf *config.Conf,
	queueMessage rabbitmq.RabbitmqMessage,
) interface{} {
	var itemForX509 *[]dpfm_api_output_formatter.ItemForX509

	for _, fn := range accepter {
		switch fn {
		case "ItemForX509":
			func() {
				itemForX509 = c.Issue(input, errs, log, conf, queueMessage)
			}()
		}
	}

	data := &dpfm_api_output_formatter.Message{
		ItemForX509: itemForX509,
	}

	return data
}

func (c *DPFMAPICaller) Issue(
	input *dpfm_api_input_reader.SDC,
	errs *[]error,
	log *logger.Logger,
	conf *config.Conf,
	queueMessage rabbitmq.RabbitmqMessage,
) *[]dpfm_api_output_formatter.ItemForX509 {
	outDir := conf.MountPath
	var results []dpfm_api_output_formatter.ItemForX509

	rootKey, err := loadPrivateKey(outDir + "/ca.key")
	if err != nil {
		fmt.Printf("Error loading private key: %v\n", err)
		return nil
	}

	rootCert, err := readCertFromFile(outDir + "/ca.crt")
	if err != nil {
		fmt.Printf("Error reading server certificate: %v\n", err)
		return nil
	}

	for _, item := range input.Message.ItemForX509 {
		result, clientCertDerByte, _ := generateClient(item, rootKey, x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Country:            []string{"JP"},
				Organization:       []string{"Latona Inc"},
				OrganizationalUnit: []string{"IT Department"},
				Locality:           []string{"Minato-ku"},
				Province:           []string{"Tokyo"},
				//CommonName:         "localhost",
				CommonName: fmt.Sprintf("%s Root CA", "localhost"),
			},
			KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageAny,
			},
			BasicConstraintsValid: true,
			NotBefore:             time.Date(2023, 12, 25, 17, 30, 0, 0, time.UTC),
			NotAfter:              time.Date(2023, 12, 25, 17, 30, 0, 0, time.UTC).Add(3 * 365 * 24 * time.Hour),
		})

		cert, err := x509.ParseCertificate(*clientCertDerByte)
		if err != nil {
			fmt.Printf("Error ParseCertificate: %v\n", err)
			return nil
		}

		err = verifyCertificateChain(rootCert, cert)
		if err != nil {
			fmt.Printf("Error verifying client certificate: %v\n", err)
			return nil
		}

		results = append(results, *result)
	}

	return &results
}

func readCertFromFile(filePath string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func verifyCertificateChain(
	root *x509.Certificate,
	cert *x509.Certificate,
) error {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)

	rootOpts := x509.VerifyOptions{
		Roots: rootPool,
	}

	_, err := cert.Verify(rootOpts)
	if err != nil {
		return fmt.Errorf("failed to verify certificate: %v", err)
	}

	fmt.Println("Certificate verified")
	return nil
}

func generateClient(
	item dpfm_api_input_reader.ItemForX509,
	rootKey *rsa.PrivateKey,
	rootTemplate x509.Certificate,
) (*dpfm_api_output_formatter.ItemForX509, *[]byte, error) {
	var data dpfm_api_output_formatter.ItemForX509

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating client key: %v", err)
	}

	clientCsrDerString, clientCsrDerByte, err := generateCSR(clientKey, item)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating client CSR: %v", err)
	}
	data.CSR = *clientCsrDerString

	bigInt := new(big.Int)
	serialNumber, success := bigInt.SetString(item.SerialNumber, 10)
	if !success {
		fmt.Println("変換に失敗しました。")
		return nil, nil, fmt.Errorf("Error converting serial number: %v", err)
	}

	//unixTimestamp, err := strconv.ParseInt(item.ExpiredDate, 10, 64)
	_, err = strconv.ParseInt(item.ExpiredDate, 10, 64)
	if err != nil {
		fmt.Println("変換エラー:", err)
		return nil, nil, fmt.Errorf("Error converting serial number: %v", err)
	}

	expiredDate := time.Unix(int64(1735052400), 0)
	if expiredDate.Before(time.Now()) {
		fmt.Println("証明書は既に期限切れです。")
	}

	clientTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageAny,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              expiredDate,
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2},
				Value: []byte("{}"),
			},
		},
	}

	clientCertDerString, clientCertDerByte, err := signCertificateOriginal(
		clientTemplate,
		*clientCsrDerByte,
		rootTemplate,
		clientKey.Public().(*rsa.PublicKey),
		rootKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Error signing client certificate: %v", err)
	}
	data.CRT = *clientCertDerString

	keyBytes := x509.MarshalPKCS1PrivateKey(clientKey)

	clientKeyPemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: keyBytes,
		},
	)
	data.Key = string(clientKeyPemData)

	return &data, clientCertDerByte, nil
}

func generateCSR(
	privateKey *rsa.PrivateKey,
	item dpfm_api_input_reader.ItemForX509,
) (*string, *[]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{item.CountryName},
			Organization:       []string{item.OrganizationName},
			OrganizationalUnit: []string{item.OrganizationalUnitName},
			Locality:           []string{item.LocalityName},
			Province:           []string{item.StateOrProvinceName},
			CommonName:         "localhost", // TODO 暫定対応
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	//clientCSRFile, err := os.Create(outDir + "/client.csr")
	//if err != nil {
	//	return nil, fmt.Errorf("Error creating client CSR file: %v", err)
	//}
	//defer clientCSRFile.Close()
	//pem.Encode(clientCSRFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		},
	)

	csrDERString := string(pemData)

	return &csrDERString, &csrDER, nil
}

func signCertificateOriginal(
	template x509.Certificate,
	csrDER []byte,
	parentTemplate x509.Certificate,
	pubKey *rsa.PublicKey,
	privKey *rsa.PrivateKey,
) (*string, *[]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature check failed: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &parentTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// x.509証明書をファイルに保存
	//clientCertFile, err := os.Create(outDir + "/client.crt")
	//if err != nil {
	//	return nil, fmt.Errorf("Error creating client certificate file: %v", err)
	//}
	//defer clientCertFile.Close()
	//pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: certDER,
		},
	)

	certDERString := string(pemData)

	return &certDERString, &certDER, nil
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error reading private key file: %v", err)
	}

	// PEMブロックを取得
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("Error decoding PEM block")
	}

	// 秘密鍵をPKCS#1形式としてパース
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing private key: %v", err)
	}

	return key, nil
}
