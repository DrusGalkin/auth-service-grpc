FROM golang:1.25

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

WORKDIR /auth

COPY . .

RUN go mod download
RUN go build -o main ./cmd/main/main.go

CMD ["./main"]