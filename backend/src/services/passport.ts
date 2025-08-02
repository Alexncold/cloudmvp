import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import { Strategy as JwtStrategy, ExtractJwt, VerifiedCallback, StrategyOptions } from 'passport-jwt';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { encrypt, hashToken } from '../utils/crypto';
import jwt from 'jsonwebtoken';

// Database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Strategy options
const jwtOptions: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromExtractors([
    ExtractJwt.fromAuthHeaderAsBearerToken(),
    (req) => {
      let token = null;
      if (req && req.cookies) {
        token = req.cookies['accessToken'];
      }
      return token;
    }
  ]),
  secretOrKey: process.env.JWT_SECRET || 'default-secret-key',
  issuer: process.env.JWT_ISSUER || 'cloudcam-api',
  audience: process.env.JWT_AUDIENCE || 'cloudcam-client',
  algorithms: ['HS256']
} as const;

// Google OAuth Strategy options
interface GoogleStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: string[];
  passReqToCallback: true;
}

const googleStrategyOptions: GoogleStrategyOptions = {
  clientID: process.env.GOOGLE_CLIENT_ID || 'dummy-client-id',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'dummy-client-secret',
  callbackURL: `${process.env.API_URL || 'http://localhost:3001'}/api/auth/google/callback`,
  scope: ['profile', 'email', 'https://www.googleapis.com/auth/drive.file'],
  passReqToCallback: true
};

/**
 * Configure JWT strategy for authenticating users with a JWT
 */
const configureJwtStrategy = (passport: any) => {
  passport.use(new JwtStrategy(
    jwtOptions,
    async (jwtPayload: any, done: VerifiedCallback) => {
      try {
        // Check if token is expired
        const now = Math.floor(Date.now() / 1000);
        if (jwtPayload.exp < now) {
          return done(null, false, { message: 'Token expired' });
        }

        // Find user in database
        const result = await pool.query(
          'SELECT id, email, name, is_verified FROM users WHERE id = $1',
          [jwtPayload.userId]
        );

        if (result.rows.length === 0) {
          return done(null, false, { message: 'User not found' });
        }

        const user = result.rows[0];
        return done(null, user);
      } catch (error) {
        logger.error('JWT Strategy Error:', error);
        return done(error, false);
      }
    }
  ));
};

/**
 * Configure Google OAuth strategy for authenticating users with Google
 */
const configureGoogleStrategy = (passport: any) => {
  passport.use(new GoogleStrategy(
    googleStrategyOptions,
    async (req: any, accessToken: string, refreshToken: string, profile: Profile, done: any) => {
      const { id, displayName, emails, photos } = profile;
      const email = emails?.[0]?.value;
      const photo = photos?.[0]?.value;

      if (!email) {
        return done(new Error('No email provided by Google'), null);
      }

      const client = await pool.connect();
      
      try {
        await client.query('BEGIN');

        // Check if user already exists with this Google ID
        let userResult = await client.query(
          'SELECT * FROM users WHERE google_id = $1',
          [id]
        );

        let user = userResult.rows[0];

        if (!user) {
          // Check if user exists with this email but no Google ID
          userResult = await client.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
          );
          user = userResult.rows[0];

          if (user) {
            // Link existing account with Google
            await client.query(
              'UPDATE users SET google_id = $1, updated_at = NOW() WHERE id = $2',
              [id, user.id]
            );
            user.google_id = id;
            logger.info(`Linked Google account to existing user: ${email}`, { userId: user.id });
          } else {
            // Create new user
            const newUserResult = await client.query(
              `INSERT INTO users (email, name, google_id, is_verified, profile_picture)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, email, name, is_verified, profile_picture`,
              [
                email,
                displayName || email.split('@')[0],
                id,
                true, // Google-verified emails are considered verified
                photo
              ]
            );
            user = newUserResult.rows[0];
            logger.info(`Created new user via Google OAuth: ${email}`, { userId: user.id });
          }
        }

        // Encrypt and store the Google refresh token if provided
        if (refreshToken) {
          const encryptedRefreshToken = encrypt(refreshToken);
          await client.query(
            'UPDATE users SET google_refresh_token = $1, updated_at = NOW() WHERE id = $2',
            [encryptedRefreshToken, user.id]
          );
        }

        await client.query('COMMIT');
        
        return done(null, user);
      } catch (error) {
        await client.query('ROLLBACK');
        logger.error('Google OAuth Error:', error);
        return done(error, null);
      } finally {
        client.release();
      }
    }
  ));
};

/**
 * Configure Passport with all strategies
 */
export const configurePassport = (passport: any) => {
  // Configure strategies
  configureJwtStrategy(passport);
  configureGoogleStrategy(passport);

  // Serialize user into the sessions
  passport.serializeUser((user: any, done: any) => {
    done(null, user.id);
  });

  // Deserialize user from the sessions
  passport.deserializeUser(async (id: string, done: any) => {
    try {
      const result = await pool.query(
        'SELECT id, email, name, is_verified FROM users WHERE id = $1',
        [id]
      );
      
      if (result.rows.length === 0) {
        return done(new Error('User not found'), null);
      }
      
      done(null, result.rows[0]);
    } catch (error) {
      logger.error('Deserialize User Error:', error);
      done(error, null);
    }
  });
};

/**
 * Middleware to check if user is authenticated
 */
export const isAuthenticated = (req: any, res: any, next: any) => {
  if (req.isAuthenticated()) {
    return next();
  }
  
  // If not authenticated with session, check for JWT
  const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req) || 
               req.cookies?.accessToken;
  
  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'You must be logged in to access this resource.'
    });
  }

  // Verify JWT
  jwt.verify(token, process.env.JWT_SECRET!, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid or expired token.'
      });
    }
    
    // Attach user to request
    req.user = user;
    next();
  });
};

/**
 * Middleware to check if user has admin role
 */
export const isAdmin = (req: any, res: any, next: any) => {
  isAuthenticated(req, res, () => {
    if (req.user.role === 'admin') {
      return next();
    }
    
    res.status(403).json({
      error: 'Forbidden',
      message: 'Admin privileges required to access this resource.'
    });
  });
};
