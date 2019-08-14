package eckey

import (
	"testing"
)

func TestGeneratingKey(t *testing.T) {
	e, err := InitECKEY()
	if err != nil {
		t.Fatal(err)
		return
	}
	m := "hello world"
	ct, err := e.ECCEncrypt([]byte(m))
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log("加密的明文 :", string(ct))

	dm, err := e.ECCDecrypt(ct)
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log("解密的明文 :", string(dm))

}

func TestSign(t *testing.T) {
	e, err := InitECKEY()
	if err != nil {
		t.Fatal(err)
		return
	}
	m := []byte("hello world")
	sign, err := e.EccSign(m)
	if err != nil {
		t.Fatal(err)
		return
	}
	v := e.EccSignVer(m, sign)
	if v {
		t.Log("驗證成功")
	} else {
		t.Fatal("驗證失敗")
	}

}
