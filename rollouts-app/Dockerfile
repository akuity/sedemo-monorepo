FROM golang:1.22 as build
WORKDIR /go/src/app
COPY . .
RUN make

FROM scratch
COPY *.html ./
COPY *.png ./
COPY *.js ./
COPY *.ico ./
COPY *.css ./
COPY --from=build /go/src/app/rollouts-demo /rollouts-demo

ARG COLOR
ENV COLOR=${COLOR}
ARG ERROR_RATE
ENV ERROR_RATE=${ERROR_RATE}
ARG LATENCY
ENV LATENCY=${LATENCY}

# These are overriden by deployment manifests
ENV STAGE=LOCAL
ENV SEMVER=LOCAL
ENV NAMESPACE=NA

ENTRYPOINT [ "/rollouts-demo" ]
