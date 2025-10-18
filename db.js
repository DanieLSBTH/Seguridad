// db.js - Configuración de PostgreSQL con seguridad
const { Pool } = require('pg');

// Configuración del pool de conexiones
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false // Necesario para Render y otros servicios
  } : false,
  max: 20, // Máximo de conexiones simultáneas
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Evento de error en el pool
pool.on('error', (err) => {
  console.error('Error inesperado en el pool de PostgreSQL:', err);
});

// Función helper para queries con logging
const query = async (text, params) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log(`Query ejecutado en ${duration}ms:`, text.substring(0, 50));
    return res;
  } catch (error) {
    console.error('Error en query:', error);
    throw error;
  }
};

// Función para verificar conexión
const testConnection = async () => {
  try {
    const result = await query('SELECT NOW()');
    console.log(' Conexión a PostgreSQL exitosa:', result.rows[0].now);
    return true;
  } catch (error) {
    console.error(' Error al conectar a PostgreSQL:', error.message);
    return false;
  }
};

// Probar conexión al iniciar
testConnection();

module.exports = {
  query,
  pool,
  testConnection
};