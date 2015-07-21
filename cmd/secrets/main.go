package main

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	stagingSecret := ("WyhHfLRuRnIq1EFy9ZzyWOMZOnwREasu0gLsbHguyHa88sX2uxb8i5sgJ7dWYOm6QvQKpKBcG6agSyW1V_lO7geo9CatcRMG")
	//prodsec := ("CmdzTtkZfukzNiQwN-wCCB4K1t1pJHh_tQiCqLuLNUkq90N1wCKgThfwfxp8R-zXLe1xdxV6R808wfSWM1HZQkdagQxxpPKX")
	dec, err := base64.URLEncoding.DecodeString(stagingSecret)
	if err != nil {
		panic(err)
	}

	//hash := []byte("$2a$10$q0SFSb.SUZQg.5MxMiEloOs43Wv/491pFEW4bRRSNlzaVHI.d9Fxe")
	hash := []byte("$2a$10$q0SFSb.SUZQg.5MxMiEloOz6x3O.40984iCpznFNX6cIThwDfQ2/W")
	//hash := []byte("$2a$10$q0SFSb.SUZQg.5MxMiEloOkjPaMT9fHbB78.X2gEBn2GiQd89/ee6")
	//	hash := []byte("$2a$10$20PWvF/14xISB/w1PxMnKeEEOa/fk7bbc06MyYtxRek2mUM22h7Za")
	err = bcrypt.CompareHashAndPassword(hash, dec)

	fmt.Println(err)

}
