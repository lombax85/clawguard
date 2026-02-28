FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ─── Runtime ──────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Copy compiled deps (includes native better-sqlite3 bindings)
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./

# Web dashboard
COPY public/ ./public/

# Example config (user mounts their own)
COPY clawguard.yaml.example ./

# Data directory for SQLite DB
RUN mkdir -p /app/data

EXPOSE 9090

CMD ["node", "dist/index.js"]
