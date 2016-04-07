// This file contains crypto related functions
package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	jose "gopkg.in/square/go-jose.v1"
	"fmt"
)

// Parse a public
func ParsePublicKey(pemBytes []byte) (*Signer, error) {

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found or passed in")
	}
	
	switch block.Type {
	case "RSA PUBLIC KEY", "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return newSigner(rsa)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
	return nil, nil
}

// Parse a private key
func ParsePrivateKey(pemBytes []byte) (*Signer, error) {

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no key found or passed in")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return newSigner(rsa)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

// creates a new signer instance with 
// rsa public or private loaded
func newSigner(k interface{}) (*Signer, error) {
	var signer *Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		signer = &Signer{ &rsa.PublicKey{}, t}
	case *rsa.PublicKey:
		signer = &Signer{ t, &rsa.PrivateKey{} }
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return signer, nil
}

type Signer struct {
	*rsa.PublicKey
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *Signer) Sign(data []byte) (string, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
	if err == nil {
		return ToHexString(sig), nil
	}
	return "", err
}

// Verify checks the message using a rsa-sha256 signature
func (r *Signer) Verify(message []byte, hexEncodedSig string) error {
	sig, err := HexDecode(hexEncodedSig)
	if err != nil {
		return errors.New("invalid signature: unable to decode from hex to string")
	} 
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, []byte(sig))
}

// Sign a string using JWS.
// Accepts a payload to sign
func (r *Signer) JWS_RSA_Sign(payload string) (string, error) {

	// create jose signer
	joseSigner, err := jose.NewSigner(jose.RS256, r.PrivateKey);
	if err != nil {
		return "", err
	}

	// sign payload
	object, err := joseSigner.Sign([]byte(payload))
	if err != nil {
		return "", err
	}

	// serialize signature to JWT style token
	signature, err := object.CompactSerialize()
	if err != nil {
		return "", err
	}

	return signature, nil
}

// Verify a signature.
// Accepts a the signature to be verified. An error is returned if 
// signature is invalid or signature could not be verified
func (r *Signer) JWS_RSA_Verify(signature string) (string, error) {
	
	// attempt to parse serialized signature
	object, err := jose.ParseSigned(signature)
	if err != nil {
		return "", errors.New("invalid signature")
	}

	// verify the signature
	output, err := object.Verify(r.PublicKey)
	if err != nil {
	    return "", errors.New("failed to verify signature")
	}

	return string(output), nil
}


// encode byte slice to base64 url string
func ToBase64(b []byte) string {
	return b64.StdEncoding.EncodeToString(b)
}

// Encode to base 64 using RAWURLEncoding
func ToBase64Raw(b []byte) string {
	return b64.RawURLEncoding.EncodeToString(b)
}

// Decode a base64 string
func FromBase64(b string) (string, error) {
	bs, err := b64.StdEncoding.DecodeString(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", bs), nil
}

// Decode from base64 using RawURLEncoding
func FromBase64Raw(b string) (string, error) {
	bs, err := b64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", bs), nil
}

// convert byte slice to hex string
func ToHexString(b []byte) string {
	return hex.EncodeToString(b)
}

// decode an hex string
func HexDecode(hexStr string) (string, error) {
	dst, err := hex.DecodeString(hexStr)
	return string(dst), err
}

// generate RSA key pair
func GenerateKeyPair() (map[string]string, error) {

	kp := make(map[string]string)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024); 
	if err != nil {
        return kp, err
    }

    // calculations to speed up private key operations and
    // some basic sanity checks
    privateKey.Precompute()
    if err = privateKey.Validate(); err != nil {
        return kp, err
    }

    // convert private key to pem encode
    privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
    privPEMData := pem.EncodeToMemory(privBlock)

    // convert public key to pem encode
    PubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        return kp, err
    }

    pubPEMData := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: PubASN1,
    })

    kp["private_key"] = string(privPEMData)
    kp["public_key"] = string(pubPEMData)

    return kp, nil
}

