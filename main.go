package main

import (
	"log"

	"github.com/jou66jou/go-ecdsa/models/eckey"
)

func main() {
	e, err := eckey.InitECKEY()
	if err != nil {
		log.Println(err)
		return
	}
	m := "hello world"
	ct, err := e.ECCEncrypt([]byte(m))
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("ct :", string(ct))

	dm, err := e.ECCDecrypt(ct)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("dm :", string(dm))
}
