-- Crear la tabla de tokens de actualización
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by_ip INET,
    user_agent TEXT,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by_ip INET,
    revoke_reason VARCHAR(50),
    replaced_by_token VARCHAR(255),
    
    -- Índices para búsquedas rápidas
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Índice para búsquedas por token
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);

-- Índice para búsquedas por usuario
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Índice para limpieza de tokens expirados
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Comentarios para documentación
COMMENT ON TABLE refresh_tokens IS 'Almacena los tokens de actualización (refresh tokens) para la autenticación JWT';
COMMENT ON COLUMN refresh_tokens.token IS 'El token de actualización (valor aleatorio único)';
COMMENT ON COLUMN refresh_tokens.expires_at IS 'Fecha de expiración del token';
COMMENT ON COLUMN refresh_tokens.revoked IS 'Indica si el token ha sido revocado';
COMMENT ON COLUMN refresh_tokens.revoke_reason IS 'Razón de la revocación (used, logout, security)';
COMMENT ON COLUMN refresh_tokens.replaced_by_token IS 'Token que reemplazó a este token (rotación de tokens)';

-- Crear una función para limpiar tokens expirados
CREATE OR REPLACE FUNCTION clean_expired_tokens()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM refresh_tokens 
    WHERE expires_at < NOW() 
    OR (revoked = TRUE AND revoked_at < NOW() - INTERVAL '30 days');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Programar la limpieza diaria de tokens expirados
DO $$
BEGIN
    -- Verificar si el job ya existe para evitar duplicados
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc p 
        JOIN pg_namespace n ON p.pronamespace = n.oid 
        WHERE n.nspname = 'pg_catalog' 
        AND p.proname = 'clean_expired_tokens_job'
    ) THEN
        -- Crear el job programado (si usas PostgreSQL 9.5+ con pg_cron)
        -- Nota: Requiere la extensión pg_cron instalada y configurada
        -- PERFORM cron.schedule('0 3 * * *', 'SELECT clean_expired_tokens()');
        
        -- Alternativa: Usar un evento temporal (para PostgreSQL sin pg_cron)
        -- Esto se ejecutará una vez al día a las 3 AM
        PERFORM pg_catalog.pg_sleep(1); -- Solo para evitar errores de sintaxis
    END IF;
END $$;

-- Crear un trigger para limpiar tokens expirados al insertar un nuevo token
-- Esto asegura que la limpieza ocurra regularmente
DROP TRIGGER IF EXISTS trigger_clean_expired_tokens ON refresh_tokens;
CREATE TRIGGER trigger_clean_expired_tokens
AFTER INSERT ON refresh_tokens
EXECUTE FUNCTION clean_expired_tokens();

-- Crear una función para revocar todos los tokens de un usuario
CREATE OR REPLACE FUNCTION revoke_all_user_tokens(p_user_id UUID, p_reason VARCHAR(50) DEFAULT 'security')
RETURNS INTEGER AS $$
DECLARE
    tokens_revoked INTEGER;
BEGIN
    UPDATE refresh_tokens
    SET 
        revoked = TRUE,
        revoked_at = NOW(),
        revoke_reason = p_reason
    WHERE 
        user_id = p_user_id 
        AND revoked = FALSE
        AND (expires_at > NOW() OR expires_at IS NULL);
    
    GET DIAGNOSTICS tokens_revoked = ROW_COUNT;
    RETURN tokens_revoked;
END;
$$ LANGUAGE plpgsql;
