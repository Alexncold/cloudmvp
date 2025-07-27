import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import SlackHook from 'winston-slack-webhook-transport';
import { logger } from '../utils/logger';
import { Request } from 'express';

type SecurityEventType = 
  | 'login_success'
  | 'login_failed'
  | 'account_locked'
  | 'password_reset'
  | 'user_created'
  | 'user_updated'
  | 'user_deleted'
  | 'role_changed'
  | 'unauthorized_access'
  | 'suspicious_activity';

interface SecurityEvent {
  type: SecurityEventType;
  userId?: string;
  ipAddress: string;
  userAgent?: string;
  metadata?: Record<string, any>;
  timestamp?: Date;
}

class SecurityLogger {
  private static instance: SecurityLogger;
  private logger: winston.Logger;
  private isInitialized = false;

  private constructor() {
    this.initializeLogger();
  }

  public static getInstance(): SecurityLogger {
    if (!SecurityLogger.instance) {
      SecurityLogger.instance = new SecurityLogger();
    }
    return SecurityLogger.instance;
  }

  private initializeLogger(): void {
    if (this.isInitialized) return;

    const transports: winston.transport[] = [
      // Consola para desarrollo
      new winston.transports.Console({
        level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      }),
      
      // Archivo rotativo diario para logs de seguridad
      new DailyRotateFile({
        filename: 'logs/security-%DATE%.log',
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
        maxSize: '20m',
        maxFiles: '30d',
        level: 'info',
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    ];

    // Agregar integración con Slack si está configurada
    if (process.env.SLACK_WEBHOOK_URL) {
      transports.push(
        new SlackHook({
          webhookUrl: process.env.SLACK_WEBHOOK_URL,
          level: 'warn', // Solo enviar advertencias y errores a Slack
          formatter: (info) => {
            return {
              text: `*[${info.level.toUpperCase()}]* ${info.message}\n` +
                    `*Tipo:* ${info.type}\n` +
                    `*Usuario:* ${info.userId || 'N/A'}\n` +
                    `*IP:* ${info.ipAddress}\n` +
                    `*Agente de usuario:* ${info.userAgent || 'N/A'}\n` +
                    (info.metadata ? `*Metadatos:* \`\`\`${JSON.stringify(info.metadata, null, 2)}\`\`\`` : '')
            };
          }
        } as any) // Usar 'as any' para evitar problemas de tipos
      );
    }

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { service: 'cloudcam-security' },
      transports
    });

    this.isInitialized = true;
  }

  private logEvent(event: SecurityEvent): void {
    if (!this.isInitialized) {
      this.initializeLogger();
    }

    const { type, userId, ipAddress, userAgent, metadata } = event;
    const logEntry = {
      type,
      userId,
      ipAddress,
      userAgent,
      metadata,
      timestamp: new Date().toISOString()
    };

    // Determinar el nivel de log basado en el tipo de evento
    let level: string;
    let message: string;

    switch (type) {
      case 'login_success':
        level = 'info';
        message = `Inicio de sesión exitoso para el usuario ${userId}`;
        break;
      case 'login_failed':
        level = 'warn';
        message = `Intento de inicio de sesión fallido para el usuario ${userId || 'desconocido'}`;
        break;
      case 'account_locked':
        level = 'warn';
        message = `Cuenta bloqueada para el usuario ${userId} debido a múltiples intentos fallidos`;
        break;
      case 'unauthorized_access':
      case 'suspicious_activity':
        level = 'error';
        message = `Actividad sospechosa detectada: ${type}`;
        break;
      default:
        level = 'info';
        message = `Evento de seguridad: ${type}`;
    }

    // Registrar el evento
    this.logger.log({
      level,
      message,
      ...logEntry
    });

    // También registrar en el logger principal
    logger[level](message, logEntry);
  }

  // Métodos específicos para diferentes tipos de eventos de seguridad
  public logLoginSuccess(userId: string, req: Request): void {
    this.logEvent({
      type: 'login_success',
      userId,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      metadata: {
        path: req.path,
        method: req.method
      }
    });
  }

  public logLoginFailure(identifier: string, req: Request, error: string): void {
    this.logEvent({
      type: 'login_failed',
      userId: identifier,
      ipAddress: req.ip,
      userAgent: req.get('user-agen'),
      metadata: {
        path: req.path,
        method: req.method,
        error
      }
    });
  }

  public logAccountLocked(userId: string, req: Request): void {
    this.logEvent({
      type: 'account_locked',
      userId,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      metadata: {
        path: req.path,
        method: req.method
      }
    });
  }

  public logUnauthorizedAccess(req: Request, reason: string): void {
    this.logEvent({
      type: 'unauthorized_access',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      metadata: {
        path: req.path,
        method: req.method,
        reason,
        headers: {
          'x-forwarded-for': req.headers['x-forwarded-for'],
          'user-agent': req.headers['user-agent']
        }
      }
    });
  }

  public logSuspiciousActivity(req: Request, details: Record<string, any>): void {
    this.logEvent({
      type: 'suspicious_activity',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      metadata: {
        path: req.path,
        method: req.method,
        ...details
      }
    });
  }

  public logUserAction(userId: string, action: string, req: Request, details?: Record<string, any>): void {
    this.logEvent({
      type: 'user_action', // Este tipo no está definido en SecurityEventType, deberías agregarlo
      userId,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      metadata: {
        action,
        path: req.path,
        method: req.method,
        ...details
      }
    });
  }
}

export const securityLogger = SecurityLogger.getInstance();
