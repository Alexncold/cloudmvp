import express = require('express');
import { healthCheck, readinessCheck } from './health.controller';

const router = express.Router();

/**
 * @openapi
 * /health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns the health status of the API
 *     tags:
 *       - Health
 *     responses:
 *       200:
 *         description: API is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "UP"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 *                 memoryUsage:
 *                   type: object
 */
router.get('/', healthCheck);

/**
 * @openapi
 * /health/ready:
 *   get:
 *     summary: Readiness check
 *     description: Checks if all required services are available
 *     tags:
 *       - Health
 *     responses:
 *       200:
 *         description: All services are ready
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "READY"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 checks:
 *                   type: object
 *                   properties:
 *                     database:
 *                       type: boolean
 *                     redis:
 *                       type: boolean
 */
router.get('/ready', readinessCheck);

export default router;
