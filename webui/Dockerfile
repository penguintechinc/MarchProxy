# MarchProxy WebUI Dockerfile
# Multi-stage build for React + TypeScript + Vite application

FROM node:20-bookworm-slim AS builder

WORKDIR /build

# Copy package files
COPY package*.json ./

# Install dependencies with fallback
RUN npm install || npm install --legacy-peer-deps

# Copy source code
COPY . .

# Build application
RUN npm run build

# Development stage
FROM node:20-bookworm-slim AS development

LABEL maintainer="MarchProxy Contributors"
LABEL description="MarchProxy WebUI - React Frontend Development"

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies with fallback
RUN npm install || npm install --legacy-peer-deps

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Health check using Node.js (no curl dependency)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "const http = require('http'); http.get('http://localhost:3000/', (res) => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1));"

# Start dev server with hot reload
CMD ["npm", "run", "dev"]

# Production stage
FROM node:20-bookworm-slim AS production

LABEL maintainer="MarchProxy Contributors"
LABEL description="MarchProxy WebUI - React Frontend"

WORKDIR /app

# Install serve globally
RUN npm install -g serve

# Copy built application from builder
COPY --from=builder /build/dist ./dist

# Create health check script
RUN echo '#!/usr/bin/env node\nconst http = require("http");\nhttp.get("http://localhost:3000/", (res) => {\n  process.exit(res.statusCode === 200 ? 0 : 1);\n}).on("error", () => process.exit(1));' > /app/healthcheck.js && chmod +x /app/healthcheck.js

# Use existing node user (UID 1000) instead of creating new one
RUN chown -R node:node /app

USER node

# Expose port
EXPOSE 3000

# Health check using Node.js
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node /app/healthcheck.js

# Serve application
CMD ["serve", "-s", "dist", "-l", "3000"]
