-- Crear la tabla de intentos de inicio de sesión fallidos
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL, -- Puede ser email, nombre de usuario, etc.
    ip_address INET NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Índices para búsquedas rápidas
    CONSTRAINT uq_identifier_ip UNIQUE (identifier, ip_address)
);

-- Índice para búsquedas por identificador
CREATE INDEX IF NOT EXISTS idx_failed_logins_identifier ON failed_login_attempts(identifier);

-- Índice para búsquedas por dirección IP
CREATE INDEX IF NOT EXISTS idx_failed_logins_ip ON failed_login_attempts(ip_address);

-- Índice para limpieza de registros antiguos
CREATE INDEX IF NOT EXISTS idx_failed_logins_attempted_at ON failed_login_attempts(attempted_at);

-- Comentarios para documentación
COMMENT ON TABLE failed_login_attempts IS 'Registra los intentos fallidos de inicio de sesión para protección contra fuerza bruta';
COMMENT ON COLUMN failed_login_attempts.identifier IS 'Identificador utilizado para el inicio de sesión (email, nombre de usuario, etc.)';
COMMENT ON COLUMN failed_login_attempts.ip_address IS 'Dirección IP desde la que se realizó el intento';
COMMENT ON COLUMN failed_login_attempts.attempt_count IS 'Número de intentos fallidos consecutivos';

-- Crear una función para limpiar registros antiguos
CREATE OR REPLACE FUNCTION clean_old_failed_attempts()
RETURNS TRIGGER AS $$
BEGIN
    -- Eliminar registros con más de 1 día de antigüedad
    DELETE FROM failed_login_attempts 
    WHERE attempted_at < NOW() - INTERVAL '1 day';
    
    -- También limpiar registros de IPs bloqueadas que ya han cumplido su tiempo
    -- Esto es útil si cambias el tiempo de bloqueo dinámicamente
    DELETE FROM failed_login_attempts
    WHERE attempted_at < NOW() - INTERVAL '15 minutes';
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Crear un trigger para limpiar registros antiguos periódicamente
-- Se activa después de cada inserción, pero la función se ejecutará como máximo una vez por minuto
CREATE OR REPLACE FUNCTION trigger_clean_old_failed_attempts()
RETURNS TRIGGER AS $$
BEGIN
    -- Solo ejecutar la limpieza aproximadamente una vez por minuto
    -- para evitar sobrecargar la base de datos
    IF (random() < 0.01) THEN -- ~1% de probabilidad de ejecutar la limpieza
        PERFORM clean_old_failed_attempts();
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Crear el trigger
DROP TRIGGER IF EXISTS trigger_clean_failed_attempts ON failed_login_attempts;
CREATE TRIGGER trigger_clean_failed_attempts
AFTER INSERT ON failed_login_attempts
EXECUTE FUNCTION trigger_clean_old_failed_attempts();

-- Función para obtener el número de intentos fallidos recientes
CREATE OR REPLACE FUNCTION get_recent_failed_attempts(
    p_identifier VARCHAR,
    p_ip_address INET,
    p_minutes INTEGER DEFAULT 15
) RETURNS INTEGER AS $$
DECLARE
    v_attempt_count INTEGER;
BEGIN
    SELECT COALESCE(SUM(attempt_count), 0) INTO v_attempt_count
    FROM failed_login_attempts
    WHERE 
        (identifier = p_identifier OR ip_address = p_ip_address)
        AND attempted_at > NOW() - (p_minutes * INTERVAL '1 minute');
        
    RETURN v_attempt_count;
END;
$$ LANGUAGE plpgsql;
