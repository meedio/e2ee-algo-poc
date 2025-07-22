# Use official Node.js LTS image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm install --production=false

# Copy source code
COPY . .

# Expose port
EXPOSE 3001

# Start the server
CMD ["npx", "ts-node-dev", "server.ts"] 