FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install
COPY . .
# VITE_API_BASE is baked into the JS bundle at build time.
# Production images must call APIM directly so JWT validation, rate limiting,
# and correlation policies run before traffic reaches the orchestrator.
ARG VITE_API_BASE=
ARG VITE_AAD_CLIENT_ID=
ARG VITE_AAD_TENANT_ID=
ENV VITE_API_BASE=${VITE_API_BASE}
ENV VITE_AAD_CLIENT_ID=${VITE_AAD_CLIENT_ID}
ENV VITE_AAD_TENANT_ID=${VITE_AAD_TENANT_ID}
RUN set -eu; \
		test -n "$VITE_API_BASE" || { echo "VITE_API_BASE is required for production frontend images"; exit 1; }; \
		test -n "$VITE_AAD_CLIENT_ID" || { echo "VITE_AAD_CLIENT_ID is required for production frontend images"; exit 1; }; \
		test -n "$VITE_AAD_TENANT_ID" || { echo "VITE_AAD_TENANT_ID is required for production frontend images"; exit 1; }; \
		case "$VITE_API_BASE" in \
			https://*/sandbox|https://*/sandbox/) ;; \
			*) echo "VITE_API_BASE must be the APIM HTTPS /sandbox endpoint"; exit 1 ;; \
		esac
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
