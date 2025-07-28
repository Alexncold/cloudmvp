#!/bin/bash
set -euo pipefail

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuración
CHECK_INTERVAL=${CHECK_INTERVAL:-60}  # Segundos entre verificaciones
MAX_RETRIES=${MAX_RETRIES:-3}         # Número máximo de reintentos
ALERT_EMAILS=${ALERT_EMAILS:-"admin@example.com"}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
LOG_FILE="/var/log/cloudcam/health_check.log"

# Crear directorio de logs si no existe
mkdir -p "$(dirname "$LOG_FILE")"

# Función para registrar mensajes en el log
log() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Función para enviar alertas
alert() {
  local message="[ALERTA] $1"
  local subject="[CloudCam] $1"
  
  log "$message"
  
  # Enviar correo electrónico
  if command -v mail &> /dev/null && [ -n "$ALERT_EMAILS" ]; then
    echo "$message" | mail -s "$subject" "$ALERT_EMAILS"
  fi
  
  # Enviar notificación a Slack
  if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"$subject\n$message\"}" \
      "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
  fi
}

# Función para verificar el estado de un servicio HTTP
check_http_service() {
  local name=$1
  local url=$2
  local expected_status=${3:-200}
  
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$url" 2>/dev/null || echo "000")
  
  if [ "$http_code" -eq "$expected_status" ]; then
    log "[OK] $name está funcionando correctamente (HTTP $http_code)"
    return 0
  else
    log "[ERROR] $name no responde correctamente (HTTP $http_code, esperado $expected_status)"
    return 1
  fi
}

# Función para verificar el uso de disco
disk_check() {
  local threshold=${1:-90}  # Porcentaje de uso máximo permitido
  local usage
  
  usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
  
  if [ "$usage" -ge "$threshold" ]; then
    alert "Uso de disco crítico: $usage%"
    return 1
  else
    log "[OK] Uso de disco: $usage%"
    return 0
  fi
}

# Función para verificar el uso de memoria
memory_check() {
  local threshold=${1:-90}  # Porcentaje de uso máximo permitido
  local usage
  
  usage=$(free | awk '/Mem/ {printf("%.0f"), $3/$2 * 100}')
  
  if [ "$usage" -ge "$threshold" ]; then
    alert "Uso de memoria crítico: $usage%"
    return 1
  else
    log "[OK] Uso de memoria: $usage%"
    return 0
  fi
}

# Función para verificar el uso de CPU
cpu_check() {
  local threshold=${1:-90}  # Porcentaje de uso máximo permitido
  local usage
  
  usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | cut -d. -f1)
  
  if [ "$usage" -ge "$threshold" ]; then
    alert "Uso de CPU crítico: $usage%"
    return 1
  else
    log "[OK] Uso de CPU: $usage%"
    return 0
  fi
}

# Función para verificar contenedores Docker
docker_check() {
  local container_name=$1
  local status
  
  if ! command -v docker &> /dev/null; then
    log "[WARNING] Docker no está instalado"
    return 0
  fi
  
  if [ -z "$container_name" ]; then
    # Verificar el servicio de Docker
    if ! docker info &> /dev/null; then
      alert "El servicio de Docker no está en ejecución"
      return 1
    fi
    log "[OK] Servicio de Docker en ejecución"
    return 0
  fi
  
  # Verificar un contenedor específico
  status=$(docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null || echo "missing")
  
  if [ "$status" != "running" ]; then
    alert "El contenedor $container_name no está en ejecución (estado: $status)"
    return 1
  else
    log "[OK] Contenedor $container_name en ejecución"
    return 0
  fi
}

# Función para verificar el estado de la base de datos
db_check() {
  local db_type=${1:-postgres}
  local db_url=${2:-postgresql://${POSTGRES_USER:-cloudcam_user}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB:-cloudcam_prod}}
  
  case $db_type in
    postgres)
      if ! command -v psql &> /dev/null; then
        log "[WARNING] psql no está instalado, omitiendo verificación de PostgreSQL"
        return 0
      fi
      
      if PGPASSWORD=$(echo "$db_url" | grep -oP '(?<=:)[^:]+(?=@)' | head -1) \
         psql -t -h "$(echo "$db_url" | grep -oP '(?<=@)[^:/]+' | head -1)" \
              -p "$(echo "$db_url" | grep -oP '(?<=:)\d+' | tail -1 || echo '5432')" \
              -U "$(echo "$db_url" | grep -oP '(?<=//)[^:]+' | head -1)" \
              -d "$(echo "$db_url" | grep -oP '(?<=/)[^/]+$' | head -1)" \
              -c "SELECT 1" &> /dev/null; then
        log "[OK] Conexión a PostgreSQL exitosa"
        return 0
      else
        alert "No se pudo conectar a la base de datos PostgreSQL"
        return 1
      fi
      ;;
    redis)
      if ! command -v redis-cli &> /dev/null; then
        log "[WARNING] redis-cli no está instalado, omitiendo verificación de Redis"
        return 0
      fi
      
      if redis-cli -h "$(echo "$db_url" | grep -oP '(?<=://)[^:/]+' | head -1)" \
                  -p "$(echo "$db_url" | grep -oP '(?<=:)\d+' | tail -1 || echo '6379')" \
                  -a "$(echo "$db_url" | grep -oP '(?<=:)[^@]+' | head -1 | cut -d: -f2-)" \
                  ping &> /dev/null; then
        log "[OK] Conexión a Redis exitosa"
        return 0
      else
        alert "No se pudo conectar a Redis"
        return 1
      fi
      ;;
    *)
      log "[WARNING] Tipo de base de datos no soportado: $db_type"
      return 0
      ;;
  esac
}

# Función principal
main() {
  log "=== Iniciando verificación de salud de CloudCam ==="
  
  # Verificar recursos del sistema
  disk_check 90
  memory_check 90
  cpu_check 90
  
  # Verificar Docker y contenedores
  docker_check ""
  docker_check "${COMPOSE_PROJECT_NAME:-cloudcam}_api_1"
  docker_check "${COMPOSE_PROJECT_NAME:-cloudcam}_postgres_1"
  docker_check "${COMPOSE_PROJECT_NAME:-cloudcam}_redis_1"
  
  # Verificar servicios HTTP
  check_http_service "API" "http://localhost:3001/health" 200
  check_http_service "Frontend" "http://localhost" 200
  
  # Verificar bases de datos
  db_check "postgres" "postgresql://${POSTGRES_USER:-cloudcam_user}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB:-cloudcam_prod}"
  db_check "redis" "redis://default:${REDIS_PASSWORD}@localhost:6379"
  
  log "=== Verificación de salud completada ===\n"
}

# Configurar temporizador para ejecución continua
if [ "$1" = "--daemon" ]; then
  log "Iniciando monitoreo continuo (intervalo: ${CHECK_INTERVAL}s)"
  
  while true; do
    main
    sleep "$CHECK_INTERVAL"
  done
else
  # Ejecutar una sola vez
  main
fi
