FROM golang:alpine

WORKDIR /app

COPY . /app/

RUN apk update && apk add --no-cache git

RUN go get ./...

RUN go build -o main .

EXPOSE 8080

CMD ["/app/main"]