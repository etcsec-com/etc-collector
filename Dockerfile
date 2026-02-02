# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Copy SQL migration files (TypeScript doesn't copy non-TS files)
RUN cp src/data/migrations/*.sql dist/data/migrations/ 2>/dev/null || true

# Stage 2: Production
FROM node:20-alpine

WORKDIR /app

# Install smbclient for SYSVOL access
RUN apk add --no-cache samba-client

# Copy package files
COPY package*.json ./

# Install ONLY production dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist

# Copy API documentation for Swagger UI
COPY docs/api ./docs/api

# Create directories for data persistence
RUN mkdir -p /app/data /app/keys /app/certs /app/logs && \
    chown -R node:node /app

# Switch to non-root user
USER node

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8443/health',(r)=>process.exit(r.statusCode===200?0:1))"

# Start server
CMD ["node", "dist/server.js"]
