// Base user interface that matches our database schema
export interface BaseUser {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  is_verified: boolean;
  verification_token?: string | null;
  verification_token_expires?: Date | null;
  reset_password_token?: string | null;
  reset_password_expires?: Date | null;
  refresh_token_hash?: string | null;
  created_at: Date;
  updated_at: Date;
  role?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface TokenPayload {
  userId: string;
  email: string;
  type: 'access' | 'refresh' | 'email-verification' | 'password-reset';
  iat?: number;
  exp?: number;
  role?: string;
}

export interface LocalUser extends Omit<BaseUser, 'password_hash' | 'refresh_token_hash'> {
  password_hash?: string;
  refresh_token_hash?: string | null;
  role?: string;
}

export interface AuthResponse {
  user: Omit<LocalUser, 'password_hash' | 'refresh_token_hash'>;
  accessToken: string;
  refreshToken?: string;
  message?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface VerifyEmailRequest {
  token: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface UpdateProfileRequest {
  name?: string;
  avatar?: string;
  preferences?: Record<string, any>;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthProviderProfile {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  provider: 'google' | 'github' | 'facebook' | 'microsoft';
}

export interface TwoFactorResponse {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export interface VerifyTwoFactorRequest {
  token: string;
  code: string;
  rememberDevice?: boolean;
}

export interface SessionInfo {
  id: string;
  userAgent: string;
  ipAddress: string;
  lastActive: Date;
  isCurrent: boolean;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  lastUsed?: Date;
  createdAt: Date;
  expiresAt?: Date;
}
