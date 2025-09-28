package jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
)

var (
	InvalidToken = fmt.Errorf("Невалидный токен")
	ErrParse     = fmt.Errorf("Невалидный формат токена")
)

func (a *JWT) ValidToken(tokenStr string) (*Claim, error) {
	claim := &Claim{}

	token, err := jwt.ParseWithClaims(tokenStr, claim, func(token *jwt.Token) (interface{}, error) {
		return os.Getenv("SECRET"), nil
	})

	if err != nil {
		return nil, fmt.Errorf("%v: %v", ErrParse, err)
	}

	if !token.Valid {
		return nil, InvalidToken
	}

	return claim, nil
}
