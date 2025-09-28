package jwt

import (
	"fmt"
	"github.com/DrusGalkin/auth-service-grpc/internal/domain/models"
	"github.com/dgrijalva/jwt-go"
	"time"
)

func (a *JWT) GenerateTokens(user models.User) (models.Tokens, error) {
	const op = "jwt.GenerateTokens"

	claim := &Claim{
		ID:    user.ID,
		Email: user.Email,
	}

	access, err := generateToken(a.AccessTTL, claim)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("%s: %v", op, err)
	}

	refresh, err := generateToken(a.RefreshTTL, claim)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("%s: %v", op, err)
	}

	return models.Tokens{
		Access:    access,
		Refresh:   refresh,
		ExpiredIn: time.Now().Add(a.AccessTTL).Unix(),
	}, nil
}

func generateToken(ttl time.Duration, claim *Claim) (string, error) {
	const op = "jwt.generateToken"
	expirationTime := time.Now().Add(ttl)

	claim.StandardClaims = jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claim)
	tokenString, err := token.SignedString(SECRET)
	if err != nil {
		return "", fmt.Errorf("%s: %v", op, err)
	}

	return tokenString, err
}
