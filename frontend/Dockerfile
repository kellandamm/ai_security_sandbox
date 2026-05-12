FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install
COPY . .
# VITE_API_BASE is baked into the JS bundle at build time.
# In production the SPA calls the frontend nginx API proxy.
ARG VITE_API_BASE=/api
ARG VITE_AAD_CLIENT_ID=
ARG VITE_AAD_TENANT_ID=
ENV VITE_API_BASE=${VITE_API_BASE}
ENV VITE_AAD_CLIENT_ID=${VITE_AAD_CLIENT_ID}
ENV VITE_AAD_TENANT_ID=${VITE_AAD_TENANT_ID}
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
