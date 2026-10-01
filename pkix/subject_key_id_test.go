package pkix

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

const (
	// The public keys below were generated with
	//   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:<curve> | openssl pkey -pubout
	//   openssl genpkey -algorithm ED25519 | openssl pkey -pubout
	// and their subject key IDs computed independently of Go by hashing the
	// subjectPublicKey BIT STRING contents, which end the DER encoding:
	//   openssl pkey -pubin -in pub.pem -outform DER | tail -c <57|65|97|133|32> | openssl dgst -binary -sha1 | openssl base64
	p224PubKeyPEM = `-----BEGIN PUBLIC KEY-----
ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEvrdB6UUhwsSu/C+kRy6FbTSAGMOD+ex4
sMQHc/UqOuNevgh53IjN9b5oKxMMAKcCF6mZe8IxvG4=
-----END PUBLIC KEY-----
`
	subjectKeyIDOfP224PubKeyBASE64 = "REr974u3Uya6xHiFk5QwuZTQRDE="
	p256PubKeyPEM                  = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEMlm0mWc4OtYicbndexRxAudB6Lq
oTD+Xv60jBwjVW5407ZlG3ycSUyeZQysWEVUO6Qz+nek6pqAPOphMSFdgQ==
-----END PUBLIC KEY-----
`
	subjectKeyIDOfP256PubKeyBASE64 = "tQcUtYtuuxs6wlkOzVJgVqHgAkg="
	p384PubKeyPEM                  = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEO2chrXW3bGnS5ygna/SGa8QIkKLm6Az2
UJTe79PFgu9H6AOkeY/uP7Wp+3eaeczCqjIlOwa41EXQOImMg1zJ9ydtS3WzNUP7
1UbbxDFy82IaBpvDDnlbaVehbqRQtADT
-----END PUBLIC KEY-----
`
	subjectKeyIDOfP384PubKeyBASE64 = "k0Q/YpMl2iX5X6MtCM8Xly3Z0J0="
	p521PubKeyPEM                  = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBAf08w22QX7vVQwTLcnxfgt6Z47kJ
zzXeTAhDOyiKXJjxzr961D40NyghHWY0bKMFg96hf85IliXZq6Xs5BrppiMBrVH8
l0H8wPP83tkgQZLQ7qxAa/f0s0DDpjsN3cpcUvCVhyyuVwW3f8vm4CANLSE7Rg6u
Q2eSMV1uPirjJ2DcwP4=
-----END PUBLIC KEY-----
`
	subjectKeyIDOfP521PubKeyBASE64 = "RUV4rwekCL4XM5zSfOP7RgVR1lk="
	// OpenSSL-generated public key, not an Intercom API token.
	ed25519PubKeyPEM = /* sadscan:disable kingfisher.intercom.1 */ `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyShFCyGaPYtGMM7pc+f4GZV1UQsWf0+/caXqq2mdMf8=
-----END PUBLIC KEY-----
`
	subjectKeyIDOfEd25519PubKeyBASE64 = "gSzoj0ncU4WUOzfEiuvo180+88g="
)

// TestGenerateSubjectKeyIDForECCKeys pins the SubjectKeyId of every supported
// ECC key type, so that issuing from an existing CA keeps producing the same
// AuthorityKeyId. P-224 is included because crypto/ecdh does not support it.
func TestGenerateSubjectKeyIDForECCKeys(t *testing.T) {
	tests := []struct {
		name   string
		pubPEM string
		wantID string
	}{
		{name: "ECDSA P-224", pubPEM: p224PubKeyPEM, wantID: subjectKeyIDOfP224PubKeyBASE64},
		{name: "ECDSA P-256", pubPEM: p256PubKeyPEM, wantID: subjectKeyIDOfP256PubKeyBASE64},
		{name: "ECDSA P-384", pubPEM: p384PubKeyPEM, wantID: subjectKeyIDOfP384PubKeyBASE64},
		{name: "ECDSA P-521", pubPEM: p521PubKeyPEM, wantID: subjectKeyIDOfP521PubKeyBASE64},
		{name: "Ed25519", pubPEM: ed25519PubKeyPEM, wantID: subjectKeyIDOfEd25519PubKeyBASE64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(tc.pubPEM))
			if block == nil {
				t.Fatal("Failed decoding public key PEM")
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatal("Failed parsing public key:", err)
			}

			id, err := GenerateSubjectKeyID(pub)
			if err != nil {
				t.Fatal("Failed generating SubjectKeyId:", err)
			}
			if got := base64.StdEncoding.EncodeToString(id); got != tc.wantID {
				t.Fatalf("SubjectKeyId = %s, want %s", got, tc.wantID)
			}
		})
	}
}
