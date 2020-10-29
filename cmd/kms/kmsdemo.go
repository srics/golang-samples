package main

import (
	"io/ioutil"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"fmt"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func main() {
	var kvName string
	kvName = os.Getenv("KEYVERSION")
	if kvName == "" {
		kvName = "projects/my-project/locations/us-central1/keyRings/kms-test-1/cryptoKeys/kms-test-1/cryptoKeyVersions/1"
	}
	message := "FooBarTest1"

	ciphertext, err := encryptAsymmetric(kvName, message)
	if err != nil {
		fmt.Printf("Error: encryptAsymmetric: %v", err)
		return
	}
	b := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Printf("\nBase64 ciphertext:\n%s\n", b)
	plaintext, err := decryptAsymmetric(kvName, ciphertext)
	if err != nil {
		fmt.Printf("Error: decryptAsymmetric: %v", err)
		return
	}
	fmt.Printf("\nResult: %s\n", string(plaintext))

	s1, err := ioutil.ReadFile("/master.enc")
	if err != nil {
		fmt.Printf("out of band encrypted file /master.enc not found, nothing else to do, err: %v\n", err)
		return
	}
	p1, err := decryptAsymmetric(kvName, []byte(s1))
	if err != nil {
		fmt.Printf("Error: decryptAsymmetric(master.enc): %v", err)
		return
	}
	fmt.Printf("\nResult(master.enc): %s\n", string(p1))
}

// decryptAsymmetric will attempt to decrypt a given ciphertext with an
// 'RSA_DECRYPT_OAEP_2048_SHA256' key from Cloud KMS.
func decryptAsymmetric(name string, ciphertext []byte) ([]byte, error) {
	// name := "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/123"
	// ciphertext := []byte("...")  // result of an asymmetric encryption call

	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %v", err)
	}

	// Build the request.
	req := &kmspb.AsymmetricDecryptRequest{
		Name:       name,
		Ciphertext: ciphertext,
	}

	// Call the API.
	result, err := client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}
	return result.Plaintext, nil
}

// encryptAsymmetric encrypts data on your local machine using an
// 'RSA_DECRYPT_OAEP_2048_SHA256' public key retrieved from Cloud KMS.
func encryptAsymmetric(name string, message string) ([]byte, error) {
	// name := "projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key/cryptoKeyVersions/123"
	// message := "Sample message"

	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %v", err)
	}

	// Retrieve the public key from Cloud KMS. This is the only operation that
	// involves Cloud KMS. The remaining operations take place on your local
	// machine.
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	// Parse the public key. Note, this example assumes the public key is in the
	// RSA format.
	block, _ := pem.Decode([]byte(response.Pem))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not rsa")
	}

	// Convert the message into bytes. Cryptographic plaintexts and
	// ciphertexts are always byte arrays.
	plaintext := []byte(message)

	// Encrypt data using the RSA public key.
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa.EncryptOAEP: %v", err)
	}
	return ciphertext, nil
}
