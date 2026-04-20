FROM alpine:3.18

RUN apk add --no-cache curl jq bash && \
    # Install kargo CLI
    curl -sSLf https://github.com/akuity/kargo/releases/download/v1.8.4/kargo-linux-amd64 -o kargo && \
    mv kargo /usr/local/bin/ && \
    chmod +x /usr/local/bin/kargo

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]