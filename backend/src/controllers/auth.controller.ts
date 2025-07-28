import { Request, Response } from 'express';
import { validationResult } from 'express-validator';
import { AuthService } from '../services/auth.service';
import { LoginRequest, RegisterRequest, RefreshTokenRequest } from '../../../shared/types/auth';
import { logger } from '../utils/logger';

export class AuthController {
  /**
   * Registra un nuevo usuario
   */
  public static async register(req: Request, res: Response): Promise<void> {
    try {
      // Validar los datos de entrada
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
      }

      const { email, password, name } = req.body as RegisterRequest;

      // Registrar al usuario
      const user = await AuthService.register(email, password, name);

      // Enviar respuesta exitosa
      res.status(201).json({
        success: true,
        message: 'Usuario registrado exitosamente',
        user
      });
    } catch (error) {
      logger.error('Error en el controlador de registro:', error);
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al registrar el usuario'
      });
    }
  }

  /**
   * Inicia sesión con email y contraseña
   */
  public static async login(req: Request, res: Response): Promise<void> {
    try {
      // Validar los datos de entrada
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
      }

      const { email, password } = req.body as LoginRequest;

      // Iniciar sesión
      const { user, tokens } = await AuthService.login(email, password);

      // Configurar cookies seguras
      this.setAuthCookies(res, tokens);

      // Enviar respuesta exitosa
      res.status(200).json({
        success: true,
        message: 'Inicio de sesión exitoso',
        user,
        tokens
      });
    } catch (error) {
      logger.error('Error en el controlador de inicio de sesión:', error);
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al iniciar sesión'
      });
    }
  }

  /**
   * Refresca el token de acceso
   */
  public static async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body as RefreshTokenRequest;

      if (!refreshToken) {
        res.status(400).json({ success: false, message: 'Token de refresco no proporcionado' });
        return;
      }

      // Refrescar el token
      const tokens = await AuthService.refreshToken(refreshToken);

      // Configurar cookies seguras
      this.setAuthCookies(res, tokens);

      // Enviar respuesta exitosa
      res.status(200).json({
        success: true,
        message: 'Token actualizado exitosamente',
        tokens
      });
    } catch (error) {
      logger.error('Error al refrescar el token:', error);
      res.status(401).json({
        success: false,
        message: 'No se pudo actualizar el token. Por favor, inicie sesión nuevamente.'
      });
    }
  }

  /**
   * Cierra la sesión del usuario
   */
  public static async logout(_req: Request, res: Response): Promise<void> {
    try {
      // Limpiar cookies de autenticación
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      
      res.status(200).json({
        success: true,
        message: 'Sesión cerrada exitosamente'
      });
    } catch (error) {
      logger.error('Error al cerrar sesión:', error);
      res.status(500).json({
        success: false,
        message: 'Error al cerrar la sesión'
      });
    }
  }

  /**
   * Obtiene el perfil del usuario autenticado
   */
  public static async getProfile(req: Request, res: Response): Promise<void> {
    try {
      // El middleware de autenticación ya debería haber agregado el usuario a la solicitud
      const user = (req as any).user;
      
      if (!user) {
        res.status(401).json({
          success: false,
          message: 'No autorizado'
        });
        return;
      }

      // Obtener datos actualizados del usuario
      const userData = await AuthService.getUserById(user.id);
      
      if (!userData) {
        res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
        return;
      }

      res.status(200).json({
        success: true,
        user: userData
      });
    } catch (error) {
      logger.error('Error al obtener el perfil del usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error al obtener el perfil del usuario'
      });
    }
  }

  /**
   * Configura las cookies de autenticación
   */
  private static setAuthCookies(res: Response, tokens: { accessToken: string; refreshToken: string }): void {
    // Configurar cookie de acceso
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutos
      path: '/'
    });

    // Configurar cookie de refresco
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      path: '/api/auth/refresh-token'
    });
  }
}

export default AuthController;
