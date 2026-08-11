FROM golang:1.25-alpine3.22 AS rclone-build

RUN apk add --no-cache ca-certificates patch

# Go's module proxy and checksum database verify the v1.74.2 source archive
# (whose signed tag resolves to b22fe981...). The small local patch switches
# the existing goftp server to RFC 4217 explicit FTPS and forces AUTH TLS;
# ClawGuard still implements no FTP parser.
RUN mkdir -p /src \
    && go mod download github.com/rclone/rclone@v1.74.2 \
    && go mod download goftp.io/server/v2@v2.0.2 \
    && cp -a "$(go env GOMODCACHE)/github.com/rclone/rclone@v1.74.2" /src/rclone \
    && cp -a "$(go env GOMODCACHE)/goftp.io/server/v2@v2.0.2" /src/goftp \
    && chmod -R u+w /src/rclone /src/goftp

COPY rclone-explicit-ftps.patch /tmp/rclone-explicit-ftps.patch
COPY goftp-security.patch /tmp/goftp-security.patch
COPY goftp-security_test.go /src/goftp/clawguard_security_test.go
COPY minimal-rclone.go /src/rclone/cmd/clawguard-rclone/main.go

RUN cd /src/goftp \
    && patch -p1 --dry-run < /tmp/goftp-security.patch \
    && patch -p1 < /tmp/goftp-security.patch \
    && gofmt -w cmd.go data_socket.go server.go session.go clawguard_security_test.go \
    && go test . \
    && cd /src/rclone \
    && patch -p1 --dry-run < /tmp/rclone-explicit-ftps.patch \
    && patch -p1 < /tmp/rclone-explicit-ftps.patch \
    && go mod edit -replace=goftp.io/server/v2=/src/goftp \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/rclone ./cmd/clawguard-rclone

FROM node:22-alpine3.22

RUN apk add --no-cache ca-certificates openssl su-exec \
    && addgroup -g 10002 ftp-gateway \
    && adduser -D -u 10002 -G ftp-gateway -h /home/ftp-gateway -s /sbin/nologin ftp-gateway \
    && mkdir -p /app /data /run/clawguard-ftp

COPY --from=rclone-build /out/rclone /usr/local/bin/rclone
COPY supervisor.js /app/supervisor.js
COPY entrypoint.sh /usr/local/sbin/clawguard-ftp-entrypoint

RUN chmod 0755 /usr/local/bin/rclone /usr/local/sbin/clawguard-ftp-entrypoint \
    && chmod 0644 /app/supervisor.js

EXPOSE 21210-21219 30000-30099

ENTRYPOINT ["/usr/local/sbin/clawguard-ftp-entrypoint"]
