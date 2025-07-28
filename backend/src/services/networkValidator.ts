import { createHash } from 'crypto';
import * as net from 'net';
import * as ipRangeCheck from 'ip-range-check';
import { logger } from '../utils/logger';
import { Redis } from 'ioredis';

// Rangos de red privados (RFC 1918 y RFC 4193)
const PRIVATE_IP_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  'fc00::/7',
  'fe80::/10',
  '::1/128',
  '127.0.0.0/8',
  '169.254.0.0/16' // Link-local
];

// Rangos de IP considerados inseguros o reservados
const UNSAFE_IP_RANGES = [
  '0.0.0.0/8',          // Red actual
  '100.64.0.0/10',      // Shared Address Space
  '127.0.0.0/8',        // Loopback
  '169.254.0.0/16',     // Link-local
  '172.16.0.0/12',      // Redes privadas
  '192.0.0.0/24',       // IETF Protocol Assignments
  '192.0.2.0/24',       // TEST-NET-1
  '192.88.99.0/24',     // 6to4 Relay Anycast
  '192.168.0.0/16',     // Redes privadas
  '198.18.0.0/15',      // Benchmarking
  '198.51.100.0/24',    // TEST-NET-2
  '203.0.113.0/24',     // TEST-NET-3
  '224.0.0.0/4',        // Multicast
  '240.0.0.0/4',        // Reservado
  '255.255.255.255/32', // Broadcast
  '::/128',             // Unspecified
  '::1/128',            // Loopback
  '::ffff:0:0/96',      // IPv4-mapped
  '100::/64',           // Discard
  '64:ff9b::/96',       // IPv4-IPv6 Translation
  '2001::/32',          // Teredo
  '2001:10::/28',       // ORCHID
  '2001:20::/28',       // ORCHIDv2
  '2001:db8::/32',      // Documentación
  'fc00::/7',           // ULA
  'fe80::/10',          // Link-local
  'ff00::/8'            // Multicast
];

// Puertos considerados sensibles o peligrosos
const SENSITIVE_PORTS = [
  21,    // FTP
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS
  80,    // HTTP
  110,   // POP3
  111,   // RPC
  135,   // MS RPC
  139,   // NetBIOS
  143,   // IMAP
  389,   // LDAP
  443,   // HTTPS
  445,   // SMB
  465,   // SMTPS
  554,   // RTSP
  587,   // SMTP Submission
  636,   // LDAPS
  873,   // rsync
  993,   // IMAPS
  995,   // POP3S
  1080,  // SOCKS
  1433,  // MS SQL
  1521,  // Oracle
  2049,  // NFS
  2375,  // Docker
  2376,  // Docker TLS
  3000,  // Aplicaciones web comunes
  3306,  // MySQL
  3389,  // RDP
  5000,  // UPnP
  5432,  // PostgreSQL
  5672,  // AMQP
  5900,  // VNC
  5984,  // CouchDB
  6379,  // Redis
  8000,  // Aplicaciones web comunes
  8080,  // HTTP alternativo
  8081,  // HTTP alternativo
  8088,  // HTTP alternativo
  8443,  // HTTPS alternativo
  9000,  // PHP-FPM
  9042,  // Cassandra
  9092,  // Kafka
  9200,  // Elasticsearch
  9300,  // Elasticsearch
  11211, // Memcached
  15672, // RabbitMQ
  27017, // MongoDB
  27018, // MongoDB
  28017, // MongoDB HTTP
  50000  // DB2
];

/**
 * Clase para validar y analizar rangos de red
 */
export class NetworkValidator {
  private redis: Redis;
  private cacheTtl: number;

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_URL?.split('://')[1]?.split(':')[0] || 'localhost',
      port: parseInt(process.env.REDIS_URL?.split(':')[2] || '6379'),
      password: process.env.REDIS_PASSWORD,
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => {
        const delay = Math.min(times * 1000, 5000);
        return delay;
      }
    });
    
    this.cacheTtl = parseInt(process.env.CACHE_TTL || '3600'); // 1 hora por defecto
  }

  /**
   * Valida un rango de red CIDR
   */
  public validateCidr(cidr: string): { isValid: boolean; reason?: string } {
    try {
      // Verificar formato básico
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) {
        return { isValid: false, reason: 'Formato CIDR no válido' };
      }

      const [ip, mask] = cidr.split('/');
      const maskValue = parseInt(mask, 10);
      
      // Validar máscara
      if (maskValue < 0 || maskValue > 32) {
        return { isValid: false, reason: 'Máscara de red no válida (debe estar entre 0 y 32)' };
      }

      // Validar dirección IP
      const ipParts = ip.split('.').map(Number);
      if (ipParts.length !== 4 || ipParts.some(part => part < 0 || part > 255)) {
        return { isValid: false, reason: 'Dirección IP no válida' };
      }

      // Verificar si la IP está en un rango privado
      if (this.isPrivateIp(ip)) {
        return { 
          isValid: true, 
          reason: 'Rango de red privada detectado',
          isPrivate: true
        };
      }

      // Verificar si la IP está en un rango inseguro
      if (this.isUnsafeIp(ip)) {
        return { 
          isValid: false, 
          reason: 'El rango de red está reservado o es potencialmente inseguro',
          isUnsafe: true
        };
      }

      return { isValid: true };
    } catch (error) {
      logger.error('Error al validar CIDR:', error);
      return { 
        isValid: false, 
        reason: 'Error al validar el rango de red',
        error: error instanceof Error ? error.message : 'Error desconocido'
      };
    }
  }

  /**
   * Valida múltiples rangos de red
   */
  public async validateRanges(
    cidrs: string[], 
    options: { checkPublic: boolean } = { checkPublic: true }
  ) {
    const results = {
      isValidRange: true,
      validRanges: [] as string[],
      invalidRanges: [] as Array<{ range: string; reason: string }>,
      securityRisks: [] as string[],
      recommendations: [] as string[],
      privateRanges: [] as string[],
      publicRanges: [] as string[],
      estimatedDeviceCount: 0,
      estimatedScanTime: 0
    };

    // Validar cada rango
    for (const cidr of cidrs) {
      const validation = this.validateCidr(cidr);
      
      if (!validation.isValid) {
        results.isValidRange = false;
        results.invalidRanges.push({
          range: cidr,
          reason: validation.reason || 'Rango no válido'
        });
        continue;
      }

      // Verificar si es un rango privado
      if (this.isPrivateIp(cidr.split('/')[0])) {
        results.privateRanges.push(cidr);
      } else if (options.checkPublic) {
        results.publicRanges.push(cidr);
      }

      results.validRanges.push(cidr);
      
      // Calcular estimaciones
      const deviceCount = this.estimateDeviceCount(cidr);
      results.estimatedDeviceCount += deviceCount;
      results.estimatedScanTime += this.estimateScanTime(deviceCount);
      
      // Verificar riesgos de seguridad
      const securityCheck = this.checkSecurityRisks(cidr);
      if (securityCheck.risks.length > 0) {
        results.securityRisks.push(...securityCheck.risks);
      }
      if (securityCheck.recommendations.length > 0) {
        results.recommendations.push(...securityCheck.recommendations);
      }
    }

    // Verificar si hay rangos públicos sin confirmación
    if (options.checkPublic && results.publicRanges.length > 0) {
      results.isValidRange = false;
      results.securityRisks.push(
        `Se detectaron ${results.publicRanges.length} rangos de red pública. ` +
        'Se recomienda escanear solo redes privadas a menos que sea absolutamente necesario.'
      );
    }

    // Verificar si hay demasiados dispositivos
    if (results.estimatedDeviceCount > 1000) {
      results.recommendations.push(
        `El escaneo estima ${results.estimatedDeviceCount} dispositivos y puede ser intensivo. ` +
        'Considere reducir el alcance del escaneo o programarlo para fuera del horario laboral.'
      );
    }

    return results;
  }

  /**
   * Verifica si una IP está en un rango privado
   */
  public isPrivateIp(ip: string): boolean {
    return ipRangeCheck(ip, PRIVATE_IP_RANGES);
  }

  /**
   * Verifica si una IP está en un rango inseguro
   */
  public isUnsafeIp(ip: string): boolean {
    return ipRangeCheck(ip, UNSAFE_IP_RANGES);
  }

  /**
   * Verifica si un puerto es sensible
   */
  public isSensitivePort(port: number): boolean {
    return SENSITIVE_PORTS.includes(port);
  }

  /**
   * Estima el número de dispositivos en un rango CIDR
   */
  public estimateDeviceCount(cidr: string): number {
    try {
      const mask = parseInt(cidr.split('/')[1], 10);
      return Math.pow(2, 32 - mask) - 2; // Restar dirección de red y broadcast
    } catch (error) {
      logger.error('Error al estimar el número de dispositivos:', error);
      return 0;
    }
  }

  /**
   * Estima el tiempo de escaneo en segundos
   */
  public estimateScanTime(deviceCount: number): number {
    // Tiempo base por dispositivo (en segundos)
    const baseTimePerDevice = 0.1;
    // Tiempo adicional por puerto sensible
    const additionalTimePerSensitivePort = 0.5;
    
    // Estimación básica
    let estimatedTime = deviceCount * baseTimePerDevice;
    
    // Añadir tiempo adicional por puertos sensibles
    estimatedTime += (deviceCount * 0.1) * additionalTimePerSensitivePort;
    
    return Math.ceil(estimatedTime);
  }

  /**
   * Verifica riesgos de seguridad en un rango CIDR
   */
  public checkSecurityRisks(cidr: string) {
    const risks: string[] = [];
    const recommendations: string[] = [];
    
    const [ip, mask] = cidr.split('/');
    const maskValue = parseInt(mask, 10);
    
    // Verificar rangos grandes
    if (maskValue < 16) {
      risks.push(`El rango ${cidr} es muy amplio (máscara /${maskValue}) y puede contener muchos dispositivos.`);
      recommendations.push(`Considere dividir el rango ${cidr} en subredes más pequeñas.`);
    }
    
    // Verificar rangos inseguros
    if (this.isUnsafeIp(ip)) {
      risks.push(`El rango ${cidr} está en un rango reservado o potencialmente inseguro.`);
      recommendations.push(`Evite escanear el rango ${cidr} a menos que sea absolutamente necesario.`);
    }
    
    // Verificar si es una red pública
    if (!this.isPrivateIp(ip)) {
      risks.push(`El rango ${cidr} parece ser una dirección IP pública.`);
      recommendations.push(
        'El escaneo de redes públicas puede ser ilegal sin autorización expresa. ' +
        'Asegúrese de tener los permisos necesarios.'
      );
    }
    
    return { risks, recommendations };
  }

  /**
   * Obtiene información de geolocalización para una IP
   * (usa caché para evitar consultas repetidas)
   */
  public async getIpGeoInfo(ip: string) {
    const cacheKey = `ip:geo:${createHash('md5').update(ip).digest('hex')}`;
    
    try {
      // Intentar obtener del caché
      const cachedData = await this.redis.get(cacheKey);
      if (cachedData) {
        return JSON.parse(cachedData);
      }
      
      // Si no está en caché, obtener de la API (simulado)
      const geoInfo = await this.fetchIpGeoInfo(ip);
      
      // Almacenar en caché
      if (geoInfo) {
        await this.redis.setex(cacheKey, this.cacheTtl, JSON.stringify(geoInfo));
      }
      
      return geoInfo;
    } catch (error) {
      logger.error('Error al obtener información de geolocalización:', error);
      return null;
    }
  }
  
  /**
   * Obtiene información de geolocalización de una IP desde una API externa
   * (implementación simulada)
   */
  private async fetchIpGeoInfo(ip: string): Promise<any> {
    // En una implementación real, aquí se haría una llamada a una API como ipinfo.io, ipapi.co, etc.
    // Por ahora, devolvemos datos simulados
    return {
      ip,
      city: 'Buenos Aires',
      region: 'Buenos Aires',
      country: 'AR',
      loc: '-34.6037,-58.3816',
      org: 'AS12345 Ejemplo S.A.',
      timezone: 'America/Argentina/Buenos_Aires'
    };
  }
  
  /**
   * Realiza un escaneo de puertos en un rango específico
   */
  public async scanPorts(
    ip: string, 
    ports: number[], 
    options: { timeout?: number, concurrency?: number } = {}
  ) {
    const { timeout = 1000, concurrency = 10 } = options;
    const openPorts: number[] = [];
    
    // Función para escanear un puerto individual
    const scanPort = (port: number): Promise<void> => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        let isResolved = false;
        
        const onError = () => {
          if (isResolved) return;
          isResolved = true;
          socket.destroy();
          resolve();
        };
        
        socket.setTimeout(timeout);
        socket.on('timeout', onError);
        socket.on('error', onError);
        
        socket.connect(port, ip, () => {
          if (isResolved) return;
          isResolved = true;
          openPorts.push(port);
          socket.end();
          resolve();
        });
      });
    };
    
    // Escanear puertos con concurrencia controlada
    const batchSize = Math.min(concurrency, ports.length);
    for (let i = 0; i < ports.length; i += batchSize) {
      const batch = ports.slice(i, i + batchSize);
      await Promise.all(batch.map(port => scanPort(port)));
    }
    
    return openPorts.sort((a, b) => a - b);
  }
  
  /**
   * Verifica si un puerto está abierto
   */
  public async isPortOpen(ip: string, port: number, timeout = 1000): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let isResolved = false;
      
      const onError = () => {
        if (isResolved) return;
        isResolved = true;
        socket.destroy();
        resolve(false);
      };
      
      socket.setTimeout(timeout);
      socket.on('timeout', onError);
      socket.on('error', onError);
      
      socket.connect(port, ip, () => {
        if (isResolved) return;
        isResolved = true;
        socket.end();
        resolve(true);
      });
    });
  }
}

// Exportar una instancia del validador
export const networkValidator = new NetworkValidator();

export default networkValidator;
