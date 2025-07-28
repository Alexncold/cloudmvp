#!/bin/bash
set -euo pipefail

# Colores para la salida
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuración por defecto
BACKUP_DIR="/var/backups/cloudcam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CURRENT_BACKUP_DIR="${BACKUP_DIR}/${TIMESTAMP}"
KEEP_DAYS=30
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cloudcam}"

# Configuración de la base de datos
POSTGRES_USER="${POSTGRES_USER:-cloudcam_user}"
POSTGRES_DB="${POSTGRES_DB:-cloudcam_prod}"
POSTGRES_CONTAINER="${COMPOSE_PROJECT_NAME}_postgres_1"
REDIS_CONTAINER="${COMPOSE_PROJECT_NAME}_redis_1"

# Función para mostrar ayuda
show_help() {
  echo "Uso: $0 [comando] [opciones]"
  echo "Comandos:"
  echo "  backup     Realizar una copia de seguridad"
  echo "  restore    Restaurar desde una copia de seguridad"
  echo "  list       Listar copias de seguridad disponibles"
  echo "  cleanup    Eliminar copias de seguridad antiguas"
  echo ""
  echo "Opciones:"
  echo "  -d, --dir DIR     Directorio de respaldo (por defecto: ${BACKUP_DIR})"
  echo "  -k, --keep DAYS   Conservar copias de seguridad por X días (por defecto: ${KEEP_DAYS})"
  echo "  -h, --help        Mostrar esta ayuda"
  exit 1
}

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

# Verificar dependencias
check_dependencies() {
  local deps=("docker" "docker-compose" "tar" "gzip")
  local missing=()
  
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      missing+=("$dep")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    error "Faltan dependencias: ${missing[*]}"
  fi
}

# Inicializar directorio de respaldos
init_backup_dir() {
  mkdir -p "${CURRENT_BACKUP_DIR}" || error "No se pudo crear el directorio de respaldo"
  success "Directorio de respaldo: ${CURRENT_BACKUP_DIR}"
}

# Realizar copia de seguridad de la base de datos PostgreSQL
backup_postgres() {
  local output_file="${CURRENT_BACKUP_DIR}/postgres.sql.gz"
  
  echo "Realizando copia de seguridad de PostgreSQL..."
  
  if ! docker exec "${POSTGRES_CONTAINER}" pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" | gzip > "${output_file}"; then
    error "Error al realizar la copia de seguridad de PostgreSQL"
  fi
  
  success "Copia de seguridad de PostgreSQL completada: ${output_file}"
}

# Realizar copia de seguridad de Redis
backup_redis() {
  local output_file="${CURRENT_BACKUP_DIR}/redis.rdb"
  
  echo "Realizando copia de seguridad de Redis..."
  
  # Forzar un guardado de Redis
  if ! docker exec "${REDIS_CONTAINER}" redis-cli SAVE; then
    warning "No se pudo forzar el guardado de Redis, continuando de todos modos..."
  fi
  
  # Copiar el archivo RDB
  if ! docker cp "${REDIS_CONTAINER}:/data/dump.rdb" "${output_file}"; then
    warning "No se pudo copiar el archivo RDB de Redis"
    return 1
  fi
  
  success "Copia de seguridad de Redis completada: ${output_file}"
}

# Realizar copia de seguridad de los volúmenesackup_volumes() {
  local volumes=(
    "${COMPOSE_PROJECT_NAME}_postgres_data"
    "${COMPOSE_PROJECT_NAME}_redis_data"
  )
  
  for volume in "${volumes[@]}"; do
    local output_file="${CURRENT_BACKUP_DIR}/${volume}.tar.gz"
    
    echo "Realizando copia de seguridad del volumen ${volume}..."
    
    if ! docker run --rm -v "${volume}:/source" -v "$(dirname "${output_file}"):/backup" \
         alpine tar czf "/backup/$(basename "${output_file}")" -C /source ./; then
      warning "Error al realizar la copia de seguridad del volumen ${volume}"
      continue
    fi
    
    success "Copia de seguridad del volumen ${volume} completada: ${output_file}"
  done
}

# Realizar copia de seguridad de los archivos de la aplicación
backup_app_files() {
  local app_dir="/var/lib/cloudcam"
  local output_file="${CURRENT_BACKUP_DIR}/app_files.tar.gz"
  
  echo "Realizando copia de seguridad de los archivos de la aplicación..."
  
  if [ ! -d "${app_dir}" ]; then
    warning "El directorio de la aplicación no existe: ${app_dir}"
    return 1
  fi
  
  if ! tar -czf "${output_file}" -C "$(dirname "${app_dir}")" "$(basename "${app_dir}")"; then
    warning "Error al realizar la copia de seguridad de los archivos de la aplicación"
    return 1
  fi
  
  success "Copia de seguridad de los archivos de la aplicación completada: ${output_file}"
}

# Realizar copia de seguridad completa
backup() {
  echo -e "\n${GREEN}=== Iniciando copia de seguridad ===${NC}\n"
  
  check_dependencies
  init_backup_dir
  
  # Realizar copias de seguridad
  backup_postgres
  backup_redis
  backup_volumes
  backup_app_files
  
  # Crear archivo de metadatos
  cat > "${CURRENT_BACKUP_DIR}/backup.info" <<- EOM
Backup realizado el: $(date)
Versión de la aplicación: $(git rev-parse --short HEAD 2>/dev/null || echo "desconocida")
Sistema: $(uname -a)
EOM
  
  # Calcular el tamaño del respaldo
  local total_size
  total_size=$(du -sh "${CURRENT_BACKUP_DIR}" | cut -f1)
  
  echo -e "\n${GREEN}=== Copia de seguridad completada con éxito ===${NC}"
  echo "Ubicación: ${CURRENT_BACKUP_DIR}"
  echo "Tamaño total: ${total_size}"
}

# Listar copias de seguridad disponibles
list_backups() {
  if [ ! -d "${BACKUP_DIR}" ]; then
    error "El directorio de respaldos no existe: ${BACKUP_DIR}"
  fi
  
  echo "Copias de seguridad disponibles en ${BACKUP_DIR}:"
  echo ""
  
  local count=0
  local total_size=0
  
  # Mostrar información de cada respaldo
  for dir in "${BACKUP_DIR}"/*/; do
    if [ -d "${dir}" ]; then
      local dir_name
      dir_name=$(basename "${dir}")
      local size
      size=$(du -sh "${dir}" 2>/dev/null | cut -f1)
      local date_str
      date_str=$(echo "${dir_name}" | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})_([0-9]{2})([0-9]{2})([0-9]{2})/\1-\2-\3 \4:\5:\6/' 2>/dev/null)
      
      if [ -f "${dir}/backup.info" ]; then
        local version
        version=$(grep "Versión" "${dir}/backup.info" | cut -d: -f2- | xargs)
        echo "- ${dir_name} (${size}, ${date_str}, ${version})"
      else
        echo "- ${dir_name} (${size}, ${date_str})"
      fi
      
      count=$((count + 1))
      total_size=$((total_size + $(du -s "${dir}" | cut -f1)))
    fi
  done
  
  echo ""
  echo "Total: ${count} copias de seguridad"
  echo "Tamaño total: $(echo "scale=2; ${total_size}/1024" | bc) MB"
}

# Restaurar base de datos PostgreSQL
restore_postgres() {
  local backup_dir=$1
  local input_file="${backup_dir}/postgres.sql.gz"
  
  if [ ! -f "${input_file}" ]; then
    warning "No se encontró el archivo de respaldo de PostgreSQL"
    return 1
  fi
  
  echo "Restaurando base de datos PostgreSQL..."
  
  # Detener la aplicación para evitar escrituras durante la restauración
  docker-compose stop api || true
  
  # Restaurar la base de datos
  if ! gunzip -c "${input_file}" | docker exec -i "${POSTGRES_CONTAINER}" psql -U "${POSTGRES_USER}" "${POSTGRES_DB}"; then
    error "Error al restaurar la base de datos PostgreSQL"
  fi
  
  # Reiniciar la aplicación
  docker-compose up -d api
  
  success "Base de datos PostgreSQL restaurada correctamente"
}

# Restaurar Redis
restore_redis() {
  local backup_dir=$1
  local input_file="${backup_dir}/redis.rdb"
  
  if [ ! -f "${input_file}" ]; then
    warning "No se encontró el archivo de respaldo de Redis"
    return 1
  }
  
  echo "Restaurando Redis..."
  
  # Detener Redis
  docker-compose stop redis || true
  
  # Copiar el archivo RDB
  if ! docker cp "${input_file}" "${REDIS_CONTAINER}:/data/dump.rdb"; then
    error "Error al copiar el archivo RDB de Redis"
  fi
  
  # Asegurarse de que el archivo tenga los permisos correctos
  docker exec "${REDIS_CONTAINER}" chown redis:redis /data/dump.rdb
  
  # Reiniciar Redis
  docker-compose up -d redis
  
  success "Redis restaurado correctamente"
}

# Restaurar volúmenes
restore_volumes() {
  local backup_dir=$1
  
  for volume_file in "${backup_dir}"/*_data.tar.gz; do
    if [ ! -f "${volume_file}" ]; then
      continue
    fi
    
    local volume_name
    volume_name=$(basename "${volume_file}" .tar.gz)
    
    echo "Restaurando volumen ${volume_name}..."
    
    # Detener los contenedores que usan este volumen
    docker-compose stop || true
    
    # Extraer el archivo de respaldo
    if ! docker run --rm -v "${volume_name}:/target" -v "$(dirname "${volume_file}"):/backup" \
         alpine sh -c "rm -rf /target/* && tar xzf /backup/$(basename "${volume_file}") -C /target --strip-components=1"; then
      error "Error al restaurar el volumen ${volume_name}"
    fi
    
    # Reiniciar los contenedores
    docker-compose up -d
    
    success "Volumen ${volume_name} restaurado correctamente"
  done
}

# Restaurar desde una copia de seguridad
restore() {
  local backup_dir="$1"
  
  if [ ! -d "${backup_dir}" ]; then
    error "El directorio de respaldo no existe: ${backup_dir}"
  fi
  
  echo -e "\n${YELLOW}=== ADVERTENCIA ===${NC}"
  echo "Estás a punto de restaurar desde una copia de seguridad."
  echo "Esto sobrescribirá los datos actuales y puede causar pérdida de información."
  read -p "¿Estás seguro de que deseas continuar? (s/n) " -n 1 -r
  echo
  
  if [[ ! $REPLY =~ ^[Ss]$ ]]; then
    echo "Operación cancelada"
    exit 0
  fi
  
  echo -e "\n${GREEN}=== Iniciando restauración ===${NC}\n"
  
  check_dependencies
  
  # Restaurar componentes
  restore_postgres "${backup_dir}"
  restore_redis "${backup_dir}"
  restore_volumes "${backup_dir}"
  
  echo -e "\n${GREEN}=== Restauración completada con éxito ===${NC}"
  echo "Es posible que necesites reiniciar la aplicación para que todos los cambios surtan efecto."
}

# Limpiar copias de seguridad antiguas
cleanup_old_backups() {
  echo "Eliminando copias de seguridad con más de ${KEEP_DAYS} días..."
  
  local deleted=0
  local freed_space=0
  
  # Encontrar y eliminar respaldos antiguos
  while IFS= read -r -d '' dir; do
    local dir_date
    dir_date=$(basename "${dir}" | cut -d_ -f1)
    local dir_timestamp
    dir_timestamp=$(date -d "${dir_date:0:4}-${dir_date:4:2}-${dir_date:6:2} ${dir_date:9:2}:${dir_date:11:2}:${dir_date:13:2}" +%s 2>/dev/null)
    local current_timestamp
    current_timestamp=$(date +%s)
    local diff_days
    diff_days=$(( (current_timestamp - dir_timestamp) / 86400 ))
    
    if [ ${diff_days} -gt ${KEEP_DAYS} ]; then
      local size
      size=$(du -s "${dir}" | cut -f1)
      
      echo "Eliminando copia de seguridad antigua: $(basename "${dir}") (${diff_days} días, $(echo "scale=2; ${size}/1024" | bc) MB)"
      
      rm -rf "${dir}"
      
      deleted=$((deleted + 1))
      freed_space=$((freed_space + size))
    fi
  done < <(find "${BACKUP_DIR}" -maxdepth 1 -type d -name "*_*_*_*_*_*" -print0 2>/dev/null)
  
  echo -e "\nSe eliminaron ${deleted} copias de seguridad"
  echo "Espacio liberado: $(echo "scale=2; ${freed_space}/1024" | bc) MB"
}

# Procesar argumentos de línea de comandos
COMMAND=""

while [[ $# -gt 0 ]]; do
  case $1 in
    backup|restore|list|cleanup)
      COMMAND=$1
      shift
      ;;
    -d|--dir)
      BACKUP_DIR="$2"
      shift 2
      ;;
    -k|--keep)
      KEEP_DAYS="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      ;;
    *)
      if [ -z "${COMMAND}" ]; then
        error "Comando no válido: $1"
      else
        # Asumir que es el argumento para restore
        BACKUP_TO_RESTORE="$1"
      fi
      shift
      ;;
  esac
done

# Ejecutar el comando solicitado
case "${COMMAND}" in
  backup)
    backup
    ;;
  restore)
    if [ -z "${BACKUP_TO_RESTORE:-}" ]; then
      error "Debe especificar una copia de seguridad para restaurar"
    fi
    restore "${BACKUP_DIR}/${BACKUP_TO_RESTORE}"
    ;;
  list)
    list_backups
    ;;
  cleanup)
    cleanup_old_backups
    ;;
  *)
    show_help
    ;;
esac

exit 0
