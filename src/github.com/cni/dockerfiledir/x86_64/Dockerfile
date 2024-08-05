FROM golang:1.19.0 as builder

ENV GOPATH /go

COPY . $GOPATH/src/github.com/cni/

WORKDIR $GOPATH/src/github.com/cni/

RUN GORACH=amd64 GOOS=linux GOGC=1500 CGO_ENABLE=0 GO111MODULE=off go install -v -a -installsuffix cgo -ldflags "-s -w " -pkgdir /tmp/cni-cgo \
    ./cmd/cni-plugin/ ./cmd/node-agent/ ./cmd/master-agent

FROM centos:7.5.1804

RUN mkdir -p /cni-plugin/bin

COPY --from=builder /go/bin/ /cni-plugin/bin/
COPY --from=builder /go/src/github.com/cni/etc/cni/net.d/ /cni-plugin/
COPY --from=builder /go/src/github.com/cni/scripts/entrypoint.py /cni-plugin/

RUN chmod +x /cni-plugin/entrypoint.py

ENTRYPOINT ["/cni-plugin/entrypoint.py"]
