package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	go_eccrypto2 "github.com/TRON-US/go-eccrypto"
	"github.com/akamensky/base58"
	"golang.org/x/crypto/ripemd160"
	"math/rand"
)

type CriptoEndereco interface {
	CreateChavePrivate() string
	CreateChavePublica()
	CreateWif()
	CreateEndereçoBitcoin()
	TOString() string
}

type EnderecoBitcoin struct {
	CriptoEndereco
	ChavePrivada string
	ChavePublica string
	WIF          string
	Endereço     string
}

func initEndereço() *EnderecoBitcoin{

	bitcoin := EnderecoBitcoin{}
	x:=EnderecoBitcoin{ChavePrivada: bitcoin.CreateChavePrivate()}
	x.CreateChavePublica()
	x.CreateWif()
	x.CreateEndereçoBitcoin()
	return &x
}

func (e *EnderecoBitcoin)CreateChavePrivate() string{

	var ChavePrivada []byte
	for i := 0; i < 32; i++ {
		r := rand.Intn(255)
		aux := byte(r)
		ChavePrivada = append(ChavePrivada, aux)
	}

	return hex.EncodeToString(ChavePrivada)

}

func (e *EnderecoBitcoin)CreateChavePublica(){

	ChavePrivadaBytes,_:=hex.DecodeString(e.ChavePrivada)
	encondPrivate:=go_eccrypto2.NewPrivateKeyFromBytes(ChavePrivadaBytes)
	e.ChavePublica= encondPrivate.PublicKey.Hex(false)

}

func (e *EnderecoBitcoin)CreateWif() {

	const Version = 128

	VersionHex:=hex.EncodeToString([]byte{Version})
	ParcialHex:=VersionHex+e.ChavePrivada

	ParcialBytes,_:=hex.DecodeString(ParcialHex)

	hash1:=sha256.Sum256(ParcialBytes)
	var hashaux []byte
	for _,b:=range hash1{
		hashaux= append(hashaux,b)
	}
	hash2:=sha256.Sum256(hashaux)
	ckecksumHex := hex.EncodeToString(hash2[:4])

	ChavePrivadaVersionChecksum:= ParcialHex+ckecksumHex
	x,_:=hex.DecodeString(ChavePrivadaVersionChecksum)
	encoded := base58.Encode(x)
	e.WIF=encoded
}

func (e *EnderecoBitcoin)CreateEndereçoBitcoin() {

	const Version="00"
	ChavePublicaBytes,_:=hex.DecodeString(e.ChavePublica)
	ChavePublicaSha256:=sha256.Sum256(ChavePublicaBytes)
	var ChavePublicaSha256AUX []byte

	for _,b:=range ChavePublicaSha256{
		ChavePublicaSha256AUX=append(ChavePublicaSha256AUX,b )
	}
	rip:=ripemd160.New()
	rip.Write(ChavePublicaSha256AUX)
	ChavePublica160:=rip.Sum(nil)
	ChavePublica160Hex:=hex.EncodeToString(ChavePublica160)
	ChavePublica160Hex=Version+ChavePublica160Hex
	ChavePublica160bytes,_:=hex.DecodeString(ChavePublica160Hex)
	hash1:=sha256.Sum256(ChavePublica160bytes)
	var hashaux []byte
	for _,b:=range hash1{
		hashaux= append(hashaux,b)
	}
	hash2:=sha256.Sum256(hashaux)
	ckecksumHex := hex.EncodeToString(hash2[:4])
	ChavePublica160Hex+=ckecksumHex
	x,_:=hex.DecodeString(ChavePublica160Hex)
	encoded := base58.Encode(x)
	e.Endereço=encoded

}

func (e EnderecoBitcoin)TOString() string{

	x:=fmt.Sprintf(" Chave Privada: %v \n ",e.ChavePrivada)
	x+=fmt.Sprintf("Chave Publica: %v \n ",e.ChavePublica)
	x+=fmt.Sprintf("WIF: %v \n ",e.WIF)
	x+=fmt.Sprintf("Endereço: %v \n ",e.Endereço)
	return x

}

func main() {
	e := initEndereço()
	println(e.TOString())
	}
