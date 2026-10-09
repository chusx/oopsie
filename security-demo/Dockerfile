FROM node:22-alpine
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts && npm cache clean --force
ARG NEXT_VERSION=14.2.24
# comparison builds override this to the first version patched for cve-2025-29927.
RUN if [ "$NEXT_VERSION" != "14.2.24" ]; then npm install --ignore-scripts --save-exact "next@$NEXT_VERSION" && npm cache clean --force; fi
COPY . .
RUN npm run build
USER node
EXPOSE 3111
CMD ["./node_modules/.bin/next","start","-p","3111","-H","0.0.0.0"]
