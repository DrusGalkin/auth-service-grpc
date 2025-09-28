package repository

import (
	"context"
	"fmt"
	"github.com/DrusGalkin/auth-service-grpc/internal/domain/models"
	"go.uber.org/zap"
)

func (a *AuthRepository) ValidateToken(ctx context.Context, token string) (models.User, error) {
	const op = "repository.ValidateToken"
	log := a.Log.With(zap.String("op", op))

	claims, err := a.Str.RDB.JWT.ValidToken(token)
	if err != nil {
		msg := fmt.Errorf("%s: %v", op, err)
		log.Error(msg.Error())
		return models.User{}, msg
	}

	return models.User{
		ID:    claims.ID,
		Email: claims.Email,
	}, nil
}
