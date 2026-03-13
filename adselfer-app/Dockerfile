# Build stage
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --production

# Copy source code
COPY backend ./backend
COPY frontend ./frontend
COPY config ./config

# Expose port
EXPOSE 3000

# Start application
# Ensure audit.log exists for volume mapping if needed
RUN touch backend/audit.log
CMD ["node", "backend/server.js"]
