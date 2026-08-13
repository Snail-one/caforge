package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"

	"caforge/internal/domain"
)

const PBKDF2Iterations = 600000

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}
type pbes2Params struct {
	KDF        algorithmIdentifier
	Encryption algorithmIdentifier
}
type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

func GenerateKey(alg domain.Algorithm, random io.Reader) (any, error) {
	if random == nil {
		random = rand.Reader
	}
	switch alg {
	case domain.ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), random)
	case domain.ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), random)
	case domain.RSA3072:
		return rsa.GenerateKey(random, 3072)
	case domain.RSA4096:
		return rsa.GenerateKey(random, 4096)
	default:
		return nil, fmt.Errorf("不支持的密钥算法 %q", alg)
	}
}

func PublicKey(private any) (any, error) {
	switch k := private.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型 %T", private)
	}
}

func MarshalPrivateKey(private any, password []byte, random io.Reader) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	enc, err := encryptPKCS8(der, password, random)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc}), nil
}

func ParsePrivateKey(data, password []byte) (any, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, errors.New("私钥不是有效的 PEM")
	}
	der := b.Bytes
	if b.Type == "ENCRYPTED PRIVATE KEY" {
		var err error
		der, err = decryptPKCS8(der, password)
		if err != nil {
			return nil, fmt.Errorf("私钥口令错误或数据损坏: %w", err)
		}
	} else if b.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("不支持的私钥 PEM 类型 %q", b.Type)
	}
	return x509.ParsePKCS8PrivateKey(der)
}

func encryptPKCS8(plain, password []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, err
	}
	key := pbkdf2(password, salt, PBKDF2Iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	prfNull, _ := asn1.Marshal(asn1.RawValue{Tag: 5})
	prf := algorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.RawValue{FullBytes: prfNull}}
	kdfDER, _ := asn1.Marshal(pbkdf2Params{Salt: salt, Iterations: PBKDF2Iterations, KeyLength: 32, PRF: prf})
	encDER, _ := asn1.Marshal(iv)
	paramsDER, _ := asn1.Marshal(pbes2Params{
		KDF:        algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfDER}},
		Encryption: algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: encDER}},
	})
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: paramsDER}},
		EncryptedData: ciphertext,
	})
}

func decryptPKCS8(der, password []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("无效的 EncryptedPrivateKeyInfo")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("仅支持 PBES2")
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) || !params.Encryption.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("不支持的 PKCS#8 加密算法")
	}
	var kp pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kp); err != nil {
		return nil, err
	}
	if kp.Iterations < PBKDF2Iterations || !kp.PRF.Algorithm.Equal(oidHMACSHA256) {
		return nil, errors.New("PKCS#8 KDF 参数不符合安全要求")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.Encryption.Parameters.FullBytes, &iv); err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(info.EncryptedData)%aes.BlockSize != 0 {
		return nil, errors.New("无效的 AES-CBC 数据")
	}
	keyLen := kp.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}
	key := pbkdf2(password, kp.Salt, kp.Iterations, keyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.EncryptedData)
	return pkcs7Unpad(plain, aes.BlockSize)
}

func pbkdf2(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	out := make([]byte, 0, keyLen)
	buf := make([]byte, 4)
	for block := 1; len(out) < keyLen; block++ {
		buf[0], buf[1], buf[2], buf[3] = byte(block>>24), byte(block>>16), byte(block>>8), byte(block)
		prf.Reset()
		prf.Write(salt)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := 0; j < hashLen; j++ {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func pkcs7Pad(in []byte, size int) []byte {
	n := size - len(in)%size
	return append(append([]byte(nil), in...), makeFilled(n, byte(n))...)
}
func makeFilled(n int, b byte) []byte {
	v := make([]byte, n)
	for i := range v {
		v[i] = b
	}
	return v
}
func pkcs7Unpad(in []byte, size int) ([]byte, error) {
	if len(in) == 0 || len(in)%size != 0 {
		return nil, errors.New("无效的填充")
	}
	n := int(in[len(in)-1])
	if n == 0 || n > size || n > len(in) {
		return nil, errors.New("无效的口令或填充")
	}
	for _, b := range in[len(in)-n:] {
		if int(b) != n {
			return nil, errors.New("无效的口令或填充")
		}
	}
	return in[:len(in)-n], nil
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("不是有效的 PEM 证书")
	}
	return x509.ParseCertificate(b.Bytes)
}

func EncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
