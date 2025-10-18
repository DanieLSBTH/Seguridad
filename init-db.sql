-- init-db.sql - Script para crear tablas de la aplicación
-- Ejecutar este script en la base de datos de PostgreSQL

-- Tabla de usuarios con medidas de seguridad
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    rol VARCHAR(50) DEFAULT 'user' CHECK (rol IN ('user', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Índices para mejorar performance
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol);

-- Tabla de logs de seguridad (opcional pero recomendado)
CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES usuarios(id),
    event_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_logs_user ON security_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_logs_event ON security_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_security_logs_date ON security_logs(created_at);

-- Insertar usuario admin de prueba (contraseña: Admin123456)
-- IMPORTANTE: Cambiar esta contraseña en producción
INSERT INTO usuarios (email, password_hash, nombre, rol) 
VALUES (
    'admin@umg.edu.gt',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzRJ5EHJ7.',
    'Administrador',
    'admin'
) ON CONFLICT (email) DO NOTHING;

-- Comentarios de documentación
COMMENT ON TABLE usuarios IS 'Tabla de usuarios del sistema con autenticación segura';
COMMENT ON COLUMN usuarios.password_hash IS 'Hash de contraseña con bcrypt (nunca almacenar contraseñas en texto plano)';
COMMENT ON TABLE security_logs IS 'Registro de eventos de seguridad para auditoría';

-- Verificar que todo se creó correctamente
SELECT 'Tablas creadas exitosamente' as status;