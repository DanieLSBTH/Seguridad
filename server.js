// server.js - Servidor principal con medidas de seguridad
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const authRoutes = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares de seguridad
app.use(helmet()); // Protección de headers HTTP
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS || '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' })); // Limitar tamaño de payload
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging básico de requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Ruta de salud (health check)
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'API de Aplicación Segura - UMG',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', uptime: process.uptime() });
});

// Rutas de autenticación
app.use('/api/auth', authRoutes);

// Manejo de rutas no encontradas
app.use((req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// Manejo global de errores
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // No exponer detalles del error en producción
  const message = process.env.NODE_ENV === 'production' 
    ? 'Error interno del servidor' 
    : err.message;
  
  res.status(err.status || 500).json({ 
    error: message,
    timestamp: new Date().toISOString()
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(` El ervidor esta corriendo en puerto ${PORT}`);
  console.log(` Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(` Medidas de seguridad: Helmet, CORS, Rate limiting`);
});

module.exports = app;