# ---- Build server----
FROM golang:1.25.1-alpine AS server-builder

ARG GIT_COMMIT
ARG GIT_DATE
ARG GIT_TAG

WORKDIR /workdir

RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "\
      -w -s \
      -X main.gitCommit=$GIT_COMMIT \
      -X main.gitDate=$GIT_DATE \
      -X main.gitTag=$GIT_TAG" \
    -o kauth .

# ---- Build web----
FROM node:20-bullseye AS web-builder

ENV CI=true

WORKDIR /workdir

RUN npm install -g corepack@latest \
  && corepack enable \
  && corepack prepare pnpm@9.0.0 --activate

COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY --chown=node:node ./web .
RUN pnpm run generate

# ---- Runtime stage ----
FROM alpine:latest

ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app

COPY --from=server-builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=server-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=server-builder /workdir/kauth /app/kauth
COPY --from=web-builder /workdir/dist /app/dist

EXPOSE 3000

ENTRYPOINT ["/app/kauth", "--config", "/config.yaml"]
