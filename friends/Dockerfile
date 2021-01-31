FROM golang:latest

ADD . /go/src/github.com/BearCloud/fa20-project-dev/friends

WORKDIR /go/src/github.com/BearCloud/fa20-project-dev/friends

RUN go mod download

RUN go build -o main .

EXPOSE 80

ENTRYPOINT [ "./main" ]