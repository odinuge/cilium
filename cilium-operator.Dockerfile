FROM docker.io/library/golang:1.14.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium
WORKDIR /go/src/github.com/cilium/cilium/operator
ARG LOCKDEBUG
ARG V
RUN make GOOS=linux LOCKDEBUG=$LOCKDEBUG PKG_BUILD=1 EXTRA_GOBUILD_FLAGS="-a -installsuffix cgo"

#FROM docker.io/library/alpine:3.9.3 as certs
#RUN apk --update add ca-certificates

FROM quay.io/cilium/cilium-runtime:2020-03-25
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium/operator/cilium-operator /usr/bin/cilium-operator
#COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /
CMD ["/usr/bin/cilium-operator"]
