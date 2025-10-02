package server

import (
	"context"
	pb "github.com/DrusGalkin/proto-gits/auth/generate"
)

func (a *AuthServer) IsAdmin(ctx context.Context, req *pb.IDRequest) (*pb.IsAdminResponse, error) {
	isAdmin, err := a.Rep.IsAdmin(ctx, int(req.Id))
	if err != nil {
		return nil, err
	}

	return &pb.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}
