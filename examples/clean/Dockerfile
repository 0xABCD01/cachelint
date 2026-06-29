# An already cache-friendly multi-stage build. `cachelint examples/clean`
# should report no findings: manifests are copied and installed before the
# broad source copy, the install uses a cache mount, apt is combined and
# cleaned, and a .dockerignore exists alongside this file.
# syntax=docker/dockerfile:1
FROM node:20-slim AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY . .
RUN npm run build

FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/dist ./dist
CMD ["node", "dist/server.js"]
