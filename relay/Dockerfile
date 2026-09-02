FROM node:22-bookworm-slim AS build

WORKDIR /workspace
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY relay/package.json relay/tsconfig.json ./relay/
RUN npm ci

COPY src ./src
COPY proto ./proto
COPY relay/src ./relay/src
RUN npm run build && npm --workspace @void/starshine-relay run build

FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY relay/package.json ./relay/
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /workspace/dist ./dist
COPY --from=build /workspace/proto ./proto
COPY --from=build /workspace/relay/dist ./relay/dist
COPY relay/public ./relay/public
COPY --chmod=755 relay/entrypoint.sh ./relay/entrypoint.sh

RUN mkdir -p /var/lib/starshine-relay /run/secrets/starshine \
    && chown -R node:node /var/lib/starshine-relay /run/secrets/starshine /app

EXPOSE 8787
ENTRYPOINT ["/app/relay/entrypoint.sh"]
CMD ["node", "relay/dist/index.js"]
