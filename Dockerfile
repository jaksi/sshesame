FROM golang as build-env
WORKDIR /go/src/sshesame
ADD . /go/src/sshesame
RUN go build -o /go/bin/sshesame
RUN sed -i 's/listen_address: .*/listen_address: 0.0.0.0:2022/' sshesame.yaml
FROM gcr.io/distroless/base
COPY --from=build-env /go/bin/sshesame /
COPY --from=build-env /go/src/sshesame/sshesame.yaml /config.yaml
EXPOSE 2022
VOLUME /data
CMD ["/sshesame", "-config", "/config.yaml", "-data_dir", "/data"]
