# A typical Node service Dockerfile with the classic cache mistake:
# the whole source is copied before `npm ci`, so dependencies reinstall
# on every single code change. Run `cachelint examples/node.Dockerfile`.
FROM node:20-slim

WORKDIR /app

COPY . .

RUN npm ci

RUN npm run build

EXPOSE 3000
CMD ["node", "dist/server.js"]
