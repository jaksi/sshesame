FROM golang as build-env
WORKDIR /go/src/sshesame
ADD . /go/src/sshesame
RUN go get -d
RUN go build -o /go/bin/sshesame
FROM gcr.io/distroless/base
COPY --from=build-env /go/bin/sshesame /
CMD ["/sshesame"]
