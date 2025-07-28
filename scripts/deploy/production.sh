#!/bin/bash
set -euo pipefail

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Función para imprimir mensajes de éxito
success() {
  echo -e "${GREEN}[✓] $1${NC}"
}

# Función para imprimir advertencias
warning() {
  echo -e "${YELLOW}[!] $1${NC}"
}

# Función para imprimir errores y salir
error() {
  echo -e "${RED}[✗] $1${NC}" >&2
  exit 1
}

# Verificar que se esté ejecutando como root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    error "Este script debe ejecutarse como root"
  fi
}

# Verificar dependencias necesarias
check_dependencies() {
  local dependencies=("docker" "docker-compose" "git" "openssl" "jq" "curl")
  local missing=()
  
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      missing+=("$dep")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    error "Faltan dependencias: ${missing[*]}"
  fi
}

# Configuración de variables
setup_environment() {
  # Directorio base del proyecto
  export PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  
  # Cargar variables de entorno desde .env si existe
  if [ -f "$PROJECT_DIR/.env" ]; then
    export $(grep -v '^#' "$PROJECT_DIR/.env" | xargs)
  else
    warning "No se encontró el archivo .env. Se utilizarán valores por defecto."
  fi
  
  # Configuración por defecto
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cloudcam}"
  export DEPLOY_ENV="${DEPLOY_ENV:-production}"
  export DOCKER_REGISTRY="${DOCKER_REGISTRY:-registry.example.com}"
  export DOCKER_NAMESPACE="${DOCKER_NAMESPACE:-cloudcam}"
  
  # Directorios importantes
  export BACKUP_DIR="${BACKUP_DIR:-/var/backups/$COMPOSE_PROJECT_NAME}"
  export LOGS_DIR="${LOGS_DIR:-/var/log/$COMPOSE_PROJECT_NAME}"
  export CERTS_DIR="${CERTS_DIR:-/etc/letsencrypt/live/$(hostname -f)}"
  
  # Crear directorios necesarios
  mkdir -p "$BACKUP_DIR" "$LOGS_DIR"
}

# Realizar copia de seguridad
backup() {
  local timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_dir="$BACKUP_DIR/$timestamp"
  
  echo -e "\n${YELLOW}Realizando copia de seguridad...${NC}"
  
  mkdir -p "$backup_dir"
  
  # Copiar volúmenes de datos
  docker run --rm -v "${COMPOSE_PROJECT_NAME}_postgres_data:/source" -v "$backup_dir:/backup" \
    alpine tar czf "/backup/postgres_data.tar.gz" -C /source ./
  
  docker run --rm -v "${COMPOSE_PROJECT_NAME}_redis_data:/source" -v "$backup_dir:/backup" \
    alpine tar czf "/backup/redis_data.tar.gz" -C /source ./
  
  # Exportar la base de datos
  docker-compose exec -T postgres pg_dump -U "${POSTGRES_USER:-cloudcam_user}" "${POSTGRES_DB:-cloudcam_prod}" > "$backup_dir/database_dump.sql"
  
  # Comprimir logs
  if [ -d "$LOGS_DIR" ]; then
    tar czf "$backup_dir/logs.tar.gz" -C "$LOGS_DIR" .
  fi
  
  success "Copia de seguridad completada en $backup_dir"
}

# Actualizar el código fuente
update_source() {
  echo -e "\n${YELLOW}Actualizando código fuente...${NC}"
  
  cd "$PROJECT_DIR"
  
  # Obtener los últimos cambios
  git fetch --all
  
  # Verificar si hay cambios locales sin confirmar
  if ! git diff --quiet; then
    warning "Hay cambios locales sin confirmar. Realizando un stash temporal."
    git stash save "Cambios temporales antes del despliegue $(date +'%Y-%m-%d %H:%M:%S')"
  fi
  
  # Cambiar a la rama de producción
  git checkout production || git checkout -b production
  
  # Actualizar a la última versión
  git pull origin production
  
  # Actualizar submódulos
  if [ -f ".gitmodules" ]; then
    git submodule update --init --recursive
  fi
  
  success "Código fuente actualizado"
}

# Configurar certificados SSL
setup_ssl() {
  echo -e "\n${YELLOW}Configurando certificados SSL...${NC}"
  
  # Verificar si ya existen certificados
  if [ -d "$CERTS_DIR" ] && [ -f "$CERTS_DIR/fullchain.pem" ] && [ -f "$CERTS_DIR/privkey.pem" ]; then
    success "Certificados SSL ya configurados en $CERTS_DIR"
    return 0
  fi
  
  # Instalar certbot si no está instalado
  if ! command -v certbot &> /dev/null; then
    warning "Certbot no encontrado. Instalando..."
    apt-get update
    apt-get install -y certbot
  fi
  
  # Obtener el dominio del entorno o usar el hostname
  local domain="${DOMAIN:-$(hostname -f)}"
  
  # Obtener certificado con Let's Encrypt
  certbot certonly --standalone -d "$domain" --non-interactive --agree-tos \
    --email "${ADMIN_EMAIL:-admin@$domain}" --http-01-port 8888
  
  # Configurar renovación automática
  echo "0 3 * * * root certbot renew --quiet --deploy-hook 'docker-compose -f $PROJECT_DIR/docker-compose.yml exec nginx nginx -s reload'" > /etc/cron.d/certbot-renew
  
  success "Certificados SSL configurados correctamente"
}

# Construir imágenes de Docker
build_images() {
  echo -e "\n${YELLOW}Construyendo imágenes de Docker...${NC}"
  
  cd "$PROJECT_DIR"
  
  # Construir imágenes
  docker-compose -f docker-compose.yml -f docker-compose.prod.yml build --no-cache
  
  # Etiquetar imágenes para el registro
  for service in api frontend; do
    docker tag "${COMPOSE_PROJECT_NAME}_${service}" "${DOCKER_REGISTRY}/${DOCKER_NAMESPACE}/${service}:${DEPLOY_ENV}"
  done
  
  success "Imágenes de Docker construidas y etiquetadas"
}

# Subir imágenes al registro (opcional)
push_images() {
  if [ "${SKIP_PUSH:-false}" = "true" ]; then
    warning "Omitiendo subida de imágenes al registro (SKIP_PUSH=true)"
    return 0
  fi
  
  echo -e "\n${YELLOW}Subiendo imágenes al registro...${NC}"
  
  # Iniciar sesión en el registro
  if [ -n "${DOCKER_USERNAME:-}" ] && [ -n "${DOCKER_PASSWORD:-}" ]; then
    echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin "$DOCKER_REGISTRY"
  fi
  
  # Subir imágenes
  for service in api frontend; do
    docker push "${DOCKER_REGISTRY}/${DOCKER_NAMESPACE}/${service}:${DEPLOY_ENV}"
  done
  
  success "Imágenes subidas al registro"
}

# Detener y eliminar contenedores
stop_containers() {
  echo -e "\n${YELLOW}Deteniendo contenedores...${NC}"
  
  cd "$PROJECT_DIR"
  
  # Detener y eliminar contenedores
  docker-compose -f docker-compose.yml -f docker-compose.prod.yml down --remove-orphans
  
  success "Contenedores detenidos y eliminados"
}

# Iniciar contenedores
start_containers() {
  echo -e "\n${YELLOW}Iniciando contenedores...${NC}"
  
  cd "$PROJECT_DIR"
  
  # Iniciar servicios en segundo plano
  docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  
  # Esperar a que los servicios estén listos
  echo -e "\n${YELLOW}Esperando a que los servicios estén listos...${NC}"
  
  local max_attempts=30
  local attempt=0
  local api_ready=false
  
  while [ "$attempt" -lt "$max_attempts" ] && [ "$api_ready" = false ]; do
    if curl -s -f "http://localhost:3001/health" | grep -q '"status":"ok"'; then
      api_ready=true
      success "API lista"
    else
      attempt=$((attempt + 1))
      echo "Esperando a que la API esté lista (intento $attempt/$max_attempts)..."
      sleep 5
    fi
  done
  
  if [ "$api_ready" = false ]; then
    warning "La API no está respondiendo después de $max_attempts intentos"
    docker-compose logs api
    error "Error al iniciar los servicios"
  fi
  
  success "Servicios iniciados correctamente"
}

# Realizar migraciones de base de datos
run_migrations() {
  echo -e "\n${YELLOW}Ejecutando migraciones...${NC}"
  
  cd "$PROJECT_DIR/backend"
  
  # Ejecutar migraciones con Alembic
  docker-compose -f ../docker-compose.yml exec -T api \
    python -m alembic upgrade head
  
  success "Migraciones aplicadas correctamente"
}

# Verificar el estado del despliegue
verify_deployment() {
  echo -e "\n${YELLOW}Verificando el despliegue...${NC}"
  
  # Verificar que los contenedores estén en ejecución
  local containers_running=$(docker ps --filter "name=${COMPOSE_PROJECT_NAME}" --format '{{.Names}}' | wc -l)
  
  if [ "$containers_running" -lt 5 ]; then
    warning "Algunos contenedores no están en ejecución"
    docker ps -a --filter "name=${COMPOSE_PROJECT_NAME}"
    error "Error en el despliegue"
  fi
  
  # Verificar estado de la API
  local api_status=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3001/health")
  
  if [ "$api_status" != "200" ]; then
    error "La API no responde correctamente (código: $api_status)"
  fi
  
  # Verificar estado del frontend
  local frontend_status=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost")
  
  if [ "$frontend_status" != "200" ] && [ "$frontend_status" != "302" ]; then
    warning "El frontend no responde correctamente (código: $frontend_status)"
  fi
  
  success "Despliegue verificado correctamente"
}

# Limpiar recursos no utilizados
cleanup() {
  echo -e "\n${YELLOW}Limpiando recursos no utilizados...${NC}"
  
  # Eliminar contenedores detenidos
  docker container prune -f
  
  # Eliminar imágenes sin etiqueta
  docker image prune -f
  
  # Eliminar redes no utilizadas
  docker network prune -f
  
  # Eliminar volúmenes no utilizados
  docker volume prune -f
  
  success "Limpieza completada"
}

# Función principal
main() {
  # Mostrar banner
  echo -e "\n${GREEN}=== Despliegue de CloudCam en producción ===${NC}\n"
  
  # Verificar requisitos
  check_root
  check_dependencies
  
  # Configurar entorno
  setup_environment
  
  # Realizar copia de seguridad
  backup
  
  # Actualizar código fuente
  update_source
  
  # Configurar SSL si es necesario
  setup_ssl
  
  # Construir imágenes
  build_images
  
  # Subir imágenes al registro (opcional)
  push_images
  
  # Detener contenedores existentes
  stop_containers
  
  # Iniciar contenedores
  start_containers
  
  # Ejecutar migraciones
  run_migrations
  
  # Verificar el despliegue
  verify_deployment
  
  # Limpiar recursos
  cleanup
  
  # Mostrar resumen
  echo -e "\n${GREEN}=== Despliegue completado con éxito ===${NC}"
  echo -e "\nURL de la aplicación: https://${DOMAIN:-$(hostname -f)}"
  echo -e "Panel de administración: https://${DOMAIN:-$(hostname -f)}/admin"
  echo -e "\nPara ver los logs: docker-compose logs -f"
}

# Ejecutar script principal
main "$@"
