import { JwtPayload } from 'jsonwebtoken';

// Import LocalUser interface from auth types
import { LocalUser } from '../auth';

declare global {
  namespace Express {
    interface Request {
      user?: LocalUser & JwtPayload & {
        type?: 'access' | 'refresh';
        role?: string; // Add role property to support admin checks
      };
    }
  }
}
