package jwtauth

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/mitchellh/mapstructure"
)

//Auth .
type Auth struct {
	Token   string `json:"token"`
	Refresh string `json:"refresh"`
	Type    string `json:"type"`
}

//User .
type Access struct {
	ID       int64  `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

//TokenAuth .
type TokenAuth struct {
	Access Access `json:"access,omitempty"`
	Exp    int64  `json:"exp,omitempty"`
	jwt.StandardClaims
}

func ExtractToken(bearToken string) string {
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

//CreateToken .
func CreateToken(tokenAuth TokenAuth, hash string) Auth {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &tokenAuth)

	tokenstring, err := token.SignedString([]byte(os.Getenv("HASH_CRYPT")))
	if err != nil {
		log.Fatalln(err)
	}

	return Auth{
		Token:   tokenstring,
		Refresh: hash,
		Type:    "refreshToken",
	}
}

//VerifyToken .
func VerifyToken(bearToken string) (bool, Access) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	access := Access{}

	token, err := jwt.Parse(bearToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("HASH_CRYPT")), nil //crie em uma variavel de ambiente
	})

	if err != nil {
		return false, access
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		mapstructure.Decode(claims["user"], &access)
	} else {
		return false, access
	}

	return true, access
}
