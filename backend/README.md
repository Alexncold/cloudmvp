# CloudCam Backend

Backend para la aplicación CloudCam, construido con Node.js, Express y TypeScript.

## Características de Autenticación

- **Registro de usuarios** con verificación por correo electrónico
- **Inicio de sesión** con email/contraseña
- **Recuperación de contraseña** con enlace seguro por correo electrónico
- **Autenticación con Google OAuth 2.0**
- **Refresh tokens** para mantener sesiones seguras
- **Protección de rutas** con middleware de autenticación
- **Rate limiting** para prevenir abusos
- **Seguridad mejorada** con Helmet, CORS y otras cabeceras HTTP

## Requisitos Previos

- Node.js 18+ (recomendado LTS)
- npm 8+
- PostgreSQL 13+
- Redis (opcional, para rate limiting en producción)

## Configuración

1. Copia el archivo `.env.example` a `.env` y configura las variables de entorno:

   ```bash
   cp .env.example .env
   ```

2. Configura las siguientes variables de entorno en el archivo `.env`:

   ```env
   # Configuración de la base de datos
   DATABASE_URL=postgresql://user:password@localhost:5432/cloudcam_dev

   # Configuración de JWT
   JWT_SECRET=tu_super_secreto_jwt
   JWT_ACCESS_TOKEN_EXPIRES_IN=15m
   JWT_REFRESH_TOKEN_EXPIRES_IN=30d
   JWT_EMAIL_VERIFICATION_EXPIRES_IN=24h
   JWT_PASSWORD_RESET_EXPIRES_IN=1h

   # Configuración de OAuth de Google
   GOOGLE_CLIENT_ID=tu_google_client_id
   GOOGLE_CLIENT_SECRET=tu_google_client_secret
   GOOGLE_CALLBACK_URL=http://localhost:3001/api/auth/google/callback

   # Configuración de correo electrónico
   SMTP_HOST=smtp.example.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_USER=tu_usuario_smtp
   SMTP_PASS=tu_contraseña_smtp
   EMAIL_FROM=CloudCam <noreply@cloudcam.com>
   EMAIL_REPLY_TO=soporte@cloudcam.com

   # Configuración de la aplicación
   NODE_ENV=development
   PORT=3001
   FRONTEND_URL=http://localhost:5173
   API_URL=http://localhost:3001
   ```

## Instalación

1. Instala las dependencias:

   ```bash
   npm install
   ```

2. Ejecuta las migraciones de la base de datos (si es necesario):

   ```bash
   npx prisma migrate dev
   ```

3. Inicia el servidor en modo desarrollo:

   ```bash
   npm run dev
   ```

   O para producción:

   ```bash
   npm run build
   npm start
   ```

## Endpoints de Autenticación

### Registrar un nuevo usuario

```http
POST /api/auth/register
```

**Cuerpo de la solicitud:**

```json
{
  "email": "usuario@ejemplo.com",
  "password": "contraseñaSegura123",
  "name": "Nombre del Usuario"
}
```

### Iniciar sesión

```http
POST /api/auth/login
```

**Cuerpo de la solicitud:**

```json
{
  "email": "usuario@ejemplo.com",
  "password": "contraseñaSegura123"
}
```

### Verificar correo electrónico

```http
GET /api/auth/verify-email?token=TOKEN_DE_VERIFICACION
```

### Refrescar token de acceso

```http
POST /api/auth/refresh-token
```

**Cuerpo de la solicitud:**

```json
{
  "refreshToken": "tu_refresh_token"
}
```

### Cerrar sesión

```http
POST /api/auth/logout
```

**Cuerpo de la solicitud:**

```json
{
  "refreshToken": "tu_refresh_token"
}
```

### Autenticación con Google

```http
GET /api/auth/google
```

## Seguridad

- **Rate Limiting**:
  - 5 intentos de inicio de sesión por IP cada 15 minutos
  - 3 registros por IP por hora
  - 100 peticiones por IP cada 15 minutos para el resto de endpoints

- **Cabeceras de Seguridad**:
  - Helmet.js para configurar cabeceras HTTP seguras
  - CORS configurado para el dominio del frontend
  - Cookies HTTP-only y Secure en producción

- **Contraseñas**:
  - Almacenadas con bcrypt (hash + salt)
  - Requisitos de fortaleza: mínimo 8 caracteres, mayúsculas, minúsculas, números y caracteres especiales

## Variables de Entorno

Revisa el archivo `.env.example` para ver todas las variables de entorno disponibles.

## Desarrollo

- **Linting**: `npm run lint`
- **Testing**: `npm test`
- **Formateo de código**: `npm run format`

## Producción

- Usa PM2 o un proceso manager similar para mantener el servidor en ejecución
- Configura HTTPS con un certificado SSL válido
- Asegúrate de que `NODE_ENV=production` esté configurado

## Solución de Problemas

### Errores Comunes

- **Error de conexión a la base de datos**: Verifica que PostgreSQL esté en ejecución y que las credenciales en `.env` sean correctas.
- **Errores de JWT**: Asegúrate de que `JWT_SECRET` esté configurado correctamente.
- **Problemas con el correo electrónico**: Verifica la configuración de SMTP en `.env`.

## Licencia

MIT
