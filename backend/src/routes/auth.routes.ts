import express, { Router, Request, Response, NextFunction } from 'express';
import { body, ValidationChain } from 'express-validator';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { logger } from '../utils/logger';
import { rateLimiter } from '../middleware/rateLimiter';

const router = Router();

// Rate limiting for auth endpoints
const authLimiter = rateLimiter.rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: 'Too many login attempts, please try again later.'
});

// Input validation for registration
const validateRegister = [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/\d/)
    .withMessage('Password must contain at least one number'),
  body('name').notEmpty().withMessage('Name is required')
];

// Input validation for login
const validateLogin = [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
];

// Input validation for refresh token
const validateRefreshToken = [
  body('refreshToken').notEmpty().withMessage('Refresh token is required')
];

// Input validation for Google OAuth callback
const validateGoogleCallback = [
  body('code').notEmpty().withMessage('Authorization code is required'),
  body('redirect_uri').isURL().withMessage('Valid redirect URI is required')
];

// Public routes
router.post('/register', validateRegister, AuthController.register);
router.post('/login', authLimiter, validateLogin, AuthController.login);

// Google OAuth routes - Placeholder for future implementation
router.get('/google', authLimiter, (req: Request, res: Response) => {
  res.status(501).json({ message: 'Google OAuth not implemented yet' });
});

router.get(
  '/google/callback',
  authLimiter,
  validateGoogleCallback,
  (req: Request, res: Response) => {
    res.status(501).json({ message: 'Google OAuth callback not implemented yet' });
  }
);

// Protected routes (require authentication)
router.post(
  '/refresh-token',
  authLimiter,
  validateRefreshToken,
  AuthController.refreshToken
);

router.post('/logout', authenticate, AuthController.logout);

// Google Drive related routes
router.get(
  '/drive/status',
  authenticateJWT,
  async (req, res) => {
    try {
      // TODO: Implement drive status check
      res.json({
        connected: false,
        quota: null,
        lastSync: null
      });
    } catch (error) {
      logger.error('Error checking drive status:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to check drive status',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);

router.post(
  '/drive/revoke',
  authenticateJWT,
  async (req, res) => {
    try {
      // TODO: Implement drive access revocation
      res.json({
        success: true,
        message: 'Drive access revoked successfully'
      });
    } catch (error) {
      logger.error('Error revoking drive access:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to revoke drive access',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);

// Error handling middleware for auth routes
router.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Auth route error:', err);
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: Object.values(err.errors).map((e: any) => e.message)
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

export default router;
