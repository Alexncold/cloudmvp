# 📹 CloudCam - Sistema de Videovigilancia Inteligente

Sistema completo de videovigilancia que detecta cámaras automáticamente, graba en Google Drive y permite monitoreo en tiempo real.

## 🚀 Comenzando

### Prerrequisitos

- Node.js 18+ (LTS recomendado)
- Docker y Docker Compose
- Git

### Configuración Inicial

1. **Clonar el repositorio**
   ```bash
   git clone <tu-repositorio>
   cd cloudcam
   ```

2. **Configurar variables de entorno**
   ```bash
   # Frontend
   cp frontend/.env.example frontend/.env
   
   # Backend
   cp backend/.env.example backend/.env
   ```
   
   Edita los archivos `.env` con tus credenciales:
   - Google OAuth credentials
   - JWT secrets (generar con: `openssl rand -base64 32`)
   - AES encryption key

3. **Iniciar servicios con Docker Compose**
   ```bash
   # Levantar base de datos y Redis
   docker-compose up -d postgres redis
   
   # En otra terminal: Iniciar backend
   cd backend
   npm install
   npm run dev
   
   # En otra terminal: Iniciar frontend
   cd ../frontend
   npm install
   npm run dev
   ```

4. **Verificar instalación**
   - Frontend: http://localhost:5173
   - API Health: http://localhost:3001/health
   - Base de datos: localhost:5432

## 🏗 Estructura del Proyecto

```
cloudcam/
├── frontend/           # Aplicación React + TypeScript + Vite
│   ├── src/
│   │   ├── components/    # Componentes UI
│   │   ├── pages/         # Vistas/Rutas
│   │   ├── stores/        # Estado global (Zustand)
│   │   ├── services/      # Llamadas a la API
│   │   └── utils/         # Utilidades
│   └── public/            # Archivos estáticos
│
├── backend/            # API Node.js + Express + TypeScript
│   ├── src/
│   │   ├── routes/        # Definición de rutas
│   │   ├── controllers/   # Lógica de negocio
│   │   ├── services/      # Servicios (ONVIF, Drive, etc.)
│   │   ├── models/        # Modelos de datos
│   │   └── workers/       # Jobs de grabación
│   └── database/          # Migraciones y seeds
│
└── shared/             # Tipos y utilidades compartidas
```

## 🛠 Comandos Útiles

### Frontend
```bash
# Servidor de desarrollo
npm run dev

# Build de producción
npm run build

# Linting
npm run lint
```

### Backend
```bash
# Servidor con hot-reload
npm run dev

# Compilar TypeScript
npm run build

# Iniciar en producción
npm start
```

### Docker
```bash
# Iniciar todos los servicios
docker-compose up -d

# Ver logs
docker-compose logs -f

# Detener servicios
docker-compose down
```

## 🔄 Despliegue

### Requisitos
- Docker y Docker Compose
- Dominio configurado (opcional para HTTPS)

### Pasos
1. Configurar variables de entorno de producción
2. Construir imágenes:
   ```bash
   docker-compose -f docker-compose.prod.yml build
   ```
3. Iniciar servicios:
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 🤝 Contribuir

1. Haz un Fork del proyecto
2. Crea tu rama (`git checkout -b feature/nueva-funcionalidad`)
3. Haz commit de tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request
