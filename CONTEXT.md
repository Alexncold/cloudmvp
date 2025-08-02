# Contexto del Proyecto CloudCam

## 🎯 Propósito

CloudCam es un sistema de gestión de cámaras de seguridad que permite:
- Descubrimiento automático de cámaras ONVIF
- Grabación de video 24/7 con encriptación opcional
- Almacenamiento local y en la nube (Google Drive)
- Monitoreo en tiempo real
- Gestión de múltiples usuarios y permisos

## 📋 Requisitos Clave

### Funcionales
1. **Gestión de Cámaras**
   - Descubrimiento automático de cámaras ONVIF
   - Configuración de grabación
   - Monitoreo en tiempo real

2. **Grabación**
   - Grabación continua 24/7
   - Encriptación E2E opcional
   - Almacenamiento local con rotación automática

3. **Almacenamiento**
   - Sincronización con Google Drive
   - Gestión de espacio en disco
   - Retención configurable

### Técnicos
- Backend: Node.js con TypeScript
- Base de datos: PostgreSQL
- Almacenamiento: Sistema de archivos + Google Drive
- Autenticación: JWT
- Contenedorización: Docker

## 🏗️ Arquitectura

### Componentes Principales
1. **API REST**
   - Gestión de usuarios y autenticación
   - Control de cámaras
   - Gestión de grabaciones

2. **Workers**
   - Grabación de video
   - Sincronización con la nube
   - Mantenimiento del sistema

3. **Base de Datos**
   - PostgreSQL para datos estructurados
   - Sistema de archivos para videos

## 🔄 Estado Actual

### Implementado
- Estructura básica del proyecto
- Servicio de descubrimiento ONVIF
- Esquema de base de datos inicial
- Autenticación JWT

### En Progreso
- Pruebas de integración
- Configuración de Docker
- Documentación

## 📂 Estructura de Directorios

```
/backend
  /src
    /controllers    # Controladores de la API
    /models         # Modelos de base de datos
    /routes         # Rutas de la API
    /services       # Lógica de negocio
    /workers        # Procesos en segundo plano
    /utils          # Utilidades
  /test            # Pruebas

/frontend          # (Futura implementación)
```

## 🔄 Flujo de Trabajo

1. **Desarrollo Local**
   - Usar Docker para consistencia
   - Siguiente paso: Configurar Docker Compose

2. **Pruebas**
   - Unitarias: Jest
   - Integración: Pruebas E2E
   - Siguiente paso: Completar pruebas de autenticación

3. **Despliegue**
   - Opciones: Docker, Kubernetes, Plataformas en la nube
   - Siguiente paso: Configurar entorno de producción

## 📝 Notas Importantes

- El proyecto sigue una arquitectura modular
- Se prioriza la seguridad en el manejo de credenciales
- Las pruebas son esenciales para garantizar la calidad

---

**Última actualización:** 2025-07-29 21:55 -03:00

> ℹ️ Este documento debe actualizarse con cualquier cambio significativo en la arquitectura o requisitos del proyecto.
