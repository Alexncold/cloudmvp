// Tipos compartidos para autenticación
export interface User {
  id: string;
  email: string;
  name: string;
  googleId?: string;
  driveFolderId?: string;
  refreshTokenEncrypted?: string;
  encryptionEnabled: boolean;
  lastQuotaCheck?: Date;
  isVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface GoogleAuthTokens {
  access_token: string;
  refresh_token: string;
  id_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

export interface RegisterRequest extends LoginRequest {
  name: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface AuthResponse {
  user: Omit<User, 'password' | 'refreshTokenEncrypted'>;
  tokens: AuthTokens;
  driveStatus?: DriveQuotaStatus;
}

export interface DriveQuotaStatus {
  usedBytes: number;
  limitBytes: number;
  usagePercent: number;
  available: number;
  warning: boolean;
  critical: boolean;
}

export interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  locale: string;
}

export interface TokenPayload {
  userId: string;
  email: string;
  role?: string;
  iat: number;
  exp: number;
}

export interface RateLimitInfo {
  count: number;
  resetTime: number;
}

export interface DriveFileMetadata {
  name: string;
  mimeType?: string;
  parents?: string[];
  description?: string;
}

export interface SegmentMetadata {
  startTime: Date;
  duration: number;
  resolution: string;
  cameraId: string;
}

export interface UploadResult {
  fileId: string;
  fileName: string;
  encrypted: boolean;
  uploadedAt: Date;
}
