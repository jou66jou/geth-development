package eckey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type ECKEY struct {
	pkey *ecdsa.PrivateKey // ecies key
}

func InitECKEY() (ECKEY, error) {
	var e = ECKEY{}
	p, err := getEcasd()
	if err != nil {
		return e, err
	}
	e.pkey = p
	return e, nil
}

// ecc(ecies)加密
func (e *ECKEY) ECCEncrypt(m []byte) ([]byte, error) {
	// ECDSA to ECIES
	prv := ecies.ImportECDSA(e.pkey)
	ct, err := ecies.Encrypt(rand.Reader, &prv.PublicKey, m, nil, nil)
	return ct, err
}

// ecc(ecies)解密
func (e *ECKEY) ECCDecrypt(ct []byte) ([]byte, error) {
	prv := ecies.ImportECDSA(e.pkey)
	m, err := prv.Decrypt(ct, nil, nil)
	return m, err
}

// 明文與私鑰進行簽名
func (e *ECKEY) EccSign(pt []byte) (sign []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, e.pkey, pt)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	rs, err := r.MarshalText()
	if err != nil {
		return nil, err
	}
	ss, err := s.MarshalText()
	if err != nil {
		return nil, err
	}
	// 將r，s合併（以“+”分割）
	var b bytes.Buffer
	b.Write(rs)
	b.Write([]byte(`+`))
	b.Write(ss)

	// 返回簽名
	return b.Bytes(), nil
}

// 驗證簽名
func (e *ECKEY) EccSignVer(pt, sign []byte) bool {
	var rint, sint big.Int
	rs := bytes.Split(sign, []byte("+"))
	rint.UnmarshalText(rs[0])
	sint.UnmarshalText(rs[1])
	// 根據公鑰和明文驗證簽名
	v := ecdsa.Verify(&e.pkey.PublicKey, pt, &rint, &sint)
	return v
}

// 帶入至少36位rnadKey，取得ecasd pri&pub key
func getEcasd() (*ecdsa.PrivateKey, error) {
	// EC初始化
	pubkeyCurve := elliptic.P256()

	// 產生公私鑰
	p, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	if err != nil {
		log.Println("GetEcasd err :", err)
		return nil, err
	}
	return p, nil
}
