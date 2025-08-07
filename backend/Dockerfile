# Etapa de construcción
FROM node:18-alpine AS builder

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar archivos de configuración
COPY package*.json ./
COPY tsconfig*.json ./
COPY ../tsconfig.base.json ./

# Instalar dependencias de desarrollo para la compilación
RUN npm ci --include=dev

# Copiar código fuente y archivos compartidos
COPY src/ ./src/
COPY ../shared/ ./shared/

# Compilar TypeScript
RUN npm run build

# Etapa de producción
FROM node:18-alpine

# Instalar dependencias de tiempo de ejecución
RUN apk add --no-cache tini

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar dependencias de producción
COPY --from=builder /app/package*.json ./

# Instalar solo dependencias de producción
RUN npm ci --only=production

# Copiar archivos compilados
COPY --from=builder /app/dist/ ./dist/

# Copiar archivos estáticos si los hay
COPY --from=builder /app/public/ ./public/

# Crear usuario no root
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

# Cambiar al usuario no root
USER appuser

# Usar tini como proceso init
ENTRYPOINT ["/sbin/tini", "--"]

# Comando de inicio
CMD ["node", "dist/index.js"]

# Variables de entorno por defecto
ENV NODE_ENV=production \
    PORT=3001 \
    LOG_LEVEL=info \
    LOG_TO_FILE=true \
    LOG_FILE_PATH=/var/log/cloudcam/backend.log \
    UPLOAD_DIR=/app/uploads \
    MAX_UPLOAD_SIZE=50MB

# Crear directorios necesarios
RUN mkdir -p /var/log/cloudcam /app/uploads

# Exponer el puerto de la aplicación
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1
