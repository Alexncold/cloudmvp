import { Request } from 'express';
import { CameraStatus } from '../../../shared/types/onvif';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        isAdmin: boolean;
      };
    }
  }
}

declare module '@prisma/client' {
  interface Camera {
    status: CameraStatus;
  }
}
