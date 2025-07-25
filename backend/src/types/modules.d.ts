// Type definitions for email service
declare module '../services/emailService' {
  interface EmailService {
    sendVerificationEmail(email: string, name: string, token: string): Promise<{ messageId: string; previewUrl?: string }>;
    sendPasswordResetEmail(email: string, name: string, token: string): Promise<{ messageId: string; previewUrl?: string }>;
    init(config?: any): Promise<EmailService>;
  }

  const emailService: EmailService;
  export default emailService;
}
