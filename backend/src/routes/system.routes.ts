import { Router } from 'express';
import { systemController } from '../controllers/system.controller';

export const systemRouter = Router();

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns the health status of the application
 *     tags: [System]
 *     responses:
 *       200:
 *         description: Application is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "healthy"
 *                 database:
 *                   type: boolean
 *                   example: true
 *                 storage:
 *                   type: boolean
 *                   example: true
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 *                   example: 123.45
 *       503:
 *         description: Service is unhealthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "degraded"
 *                 database:
 *                   type: boolean
 *                   example: false
 *                 storage:
 *                   type: boolean
 *                   example: true
 */
systemRouter.get('/health', systemController.healthCheck.bind(systemController));

/**
 * @swagger
 * /system/info:
 *   get:
 *     summary: Get system information
 *     description: Returns detailed system information and metrics
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 node:
 *                   type: object
 *                   properties:
 *                     version:
 *                       type: string
 *                       example: "v16.14.0"
 *                     platform:
 *                       type: string
 *                       example: "linux"
 *                     memoryUsage:
 *                       type: object
 *                       properties:
 *                         rss:
 *                           type: number
 *                           example: 12345678
 *                         heapTotal:
 *                           type: number
 *                           example: 1234567
 *                         heapUsed:
 *                           type: number
 *                           example: 123456
 *                     uptime:
 *                       type: number
 *                       example: 123.45
 *                 database:
 *                   type: object
 *                   properties:
 *                     version:
 *                       type: string
 *                       example: "PostgreSQL 13.4 on x86_64-pc-linux-musl, compiled by gcc (Alpine 10.3.1_git20210424) 10.3.1 20210424, 64-bit"
 *                     maxConnections:
 *                       type: number
 *                       example: 100
 *                     activeConnections:
 *                       type: number
 *                       example: 5
 *                 storage:
 *                   type: object
 *                   properties:
 *                     usedMB:
 *                       type: number
 *                       example: 123.45
 *                     maxMB:
 *                       type: number
 *                       example: 10240
 *                     usagePercent:
 *                       type: number
 *                       example: 1.2
 *                     path:
 *                       type: string
 *                       example: "/app/storage"
 *                 environment:
 *                   type: string
 *                   example: "development"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 */
systemRouter.get('/system/info', systemController.systemInfo.bind(systemController));

export default systemRouter;
