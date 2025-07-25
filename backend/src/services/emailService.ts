import nodemailer from 'nodemailer';
import { createTransport, Transporter } from 'nodemailer';
import { readFileSync } from 'fs';
import { join } from 'path';
import handlebars from 'handlebars';
import { logger } from '../utils/logger';

// Email template cache
const templateCache: Record<string, HandlebarsTemplateDelegate> = {};

// Email configuration
type EmailConfig = {
  host: string;
  port: number;
  secure: boolean;
  auth?: {
    user: string;
    pass: string;
  };
  from: string;
  replyTo?: string;
  logoUrl: string;
  frontendUrl: string;
};

// Default email configuration (can be overridden by environment variables)
const defaultConfig: EmailConfig = {
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: parseInt(process.env.SMTP_PORT || '2525'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: process.env.SMTP_USER && process.env.SMTP_PASS
    ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      }
    : undefined,
  from: process.env.EMAIL_FROM || 'CloudCam <noreply@cloudcam.com>',
  replyTo: process.env.EMAIL_REPLY_TO || 'soporte@cloudcam.com',
  logoUrl: process.env.EMAIL_LOGO_URL || 'https://cloudcam.com/logo.png',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
};

// Create a test account if no SMTP credentials are provided
const createTestAccount = async (): Promise<nodemailer.TestAccount> => {
  if (process.env.NODE_ENV === 'test') {
    return {
      user: 'test',
      pass: 'test',
      web: 'http://localhost:1080',
      smtp: { host: 'localhost', port: 1025, secure: false },
      imap: { host: 'localhost', port: 1143, secure: false },
      pop3: { host: 'localhost', port: 1100, secure: false },
    };
  }
  
  return await nodemailer.createTestAccount();
};

// Email service class
export class EmailService {
  private transporter: Transporter;
  private config: EmailConfig;
  private isTest: boolean;

  constructor(config: Partial<EmailConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.isTest = !this.config.auth?.user || !this.config.auth?.pass;
    
    if (this.isTest) {
      logger.warn('No SMTP credentials provided. Using test account.');
    }
    
    this.transporter = createTransport({
      host: this.config.host,
      port: this.config.port,
      secure: this.config.secure,
      auth: this.config.auth,
    });
  }

  /**
   * Initialize the email service
   */
  public static async init(config: Partial<EmailConfig> = {}): Promise<EmailService> {
    const instance = new EmailService(config);
    
    if (instance.isTest) {
      const testAccount = await createTestAccount();
      
      instance.transporter = createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      
      // Log test account URL in development
      if (process.env.NODE_ENV !== 'test') {
        logger.info(`Test email account: ${testAccount.web}`);
      }
    }
    
    // Verify connection configuration
    try {
      await instance.transporter.verify();
      logger.info('Email service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      throw new Error('Failed to initialize email service');
    }
    
    return instance;
  }

  /**
   * Compile an email template
   */
  private async getTemplate(templateName: string): Promise<HandlebarsTemplateDelegate> {
    if (templateCache[templateName]) {
      return templateCache[templateName];
    }

    try {
      const templatePath = join(__dirname, `../../emails/templates/${templateName}.hbs`);
      const templateSource = readFileSync(templatePath, 'utf8');
      const template = handlebars.compile(templateSource);
      
      // Cache the compiled template
      templateCache[templateName] = template;
      
      return template;
    } catch (error) {
      logger.error(`Failed to load email template: ${templateName}`, error);
      throw new Error(`Failed to load email template: ${templateName}`);
    }
  }

  /**
   * Send an email
   */
  public async sendEmail(
    to: string,
    subject: string,
    templateName: string,
    templateData: Record<string, any>
  ): Promise<{ messageId: string; previewUrl?: string }> {
    try {
      // Get and compile the template
      const template = await this.getTemplate(templateName);
      
      // Add common template variables
      const templateContext = {
        ...templateData,
        logoUrl: this.config.logoUrl,
        frontendUrl: this.config.frontendUrl,
        currentYear: new Date().getFullYear(),
      };
      
      // Render the email content
      const html = template(templateContext);
      
      // Send the email
      const info = await this.transporter.sendMail({
        from: this.config.from,
        to,
        subject,
        html,
        replyTo: this.config.replyTo,
      });
      
      // Log email info
      logger.info(`Email sent to ${to}`, {
        messageId: info.messageId,
        template: templateName,
        previewUrl: this.isTest ? nodemailer.getTestMessageUrl(info) || undefined : undefined,
      });
      
      return {
        messageId: info.messageId,
        previewUrl: this.isTest ? nodemailer.getTestMessageUrl(info) || undefined : undefined,
      };
    } catch (error) {
      logger.error('Failed to send email:', error);
      throw new Error('Failed to send email');
    }
  }

  /**
   * Send verification email
   */
  public async sendVerificationEmail(
    email: string,
    name: string,
    token: string
  ): Promise<{ messageId: string; previewUrl?: string }> {
    const verificationUrl = `${this.config.frontendUrl}/verify-email?token=${token}`;
    
    return this.sendEmail(
      email,
      'Verifica tu correo electrónico - CloudCam',
      'verify-email',
      {
        name,
        verificationUrl,
      }
    );
  }

  /**
   * Send password reset email
   */
  public async sendPasswordResetEmail(
    email: string,
    name: string,
    token: string
  ): Promise<{ messageId: string; previewUrl?: string }> {
    const resetUrl = `${this.config.frontendUrl}/reset-password?token=${token}`;
    
    return this.sendEmail(
      email,
      'Restablece tu contraseña - CloudCam',
      'reset-password',
      {
        name,
        resetUrl,
      }
    );
  }
}

// Create and initialize singleton instance
let emailService: EmailService = new EmailService();

export const initEmailService = async (config: Partial<EmailConfig> = {}) => {
  if (!emailService) {
    emailService = await EmailService.init(config);
  }
  return emailService;
};

// Export the singleton instance
export const sendVerificationEmail = async (
  email: string,
  name: string,
  token: string
) => {
  if (!emailService) {
    await initEmailService();
  }
  return emailService.sendVerificationEmail(email, name, token);
};

export const sendPasswordResetEmail = async (
  email: string,
  name: string,
  token: string
) => {
  if (!emailService) {
    await initEmailService();
  }
  return emailService.sendPasswordResetEmail(email, name, token);
};

export default emailService;
