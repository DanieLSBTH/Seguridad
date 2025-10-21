// middleware.js - Middleware de seguridad y autenticación
const jwt = require('jsonwebtoken');

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log(' Token inválido o expirado');
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }

    req.user = user; // Agregar info del usuario al request
    next();
  });
};

// Rate limiting simple (prevenir fuerza bruta)
const rateLimitStore = new Map();

const rateLimiter = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutos
  const maxRequests = 10; // máximo 10 requests por ventana

  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, []);
  }

  const requests = rateLimitStore.get(ip);
  
  // Limpiar requests antiguos
  const recentRequests = requests.filter(time => now - time < windowMs);
  
  if (recentRequests.length >= maxRequests) {
    console.log(` Rate limit excedido para IP: ${ip}`);
    return res.status(429).json({ 
      error: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' 
    });
  }

  recentRequests.push(now);
  rateLimitStore.set(ip, recentRequests);
  
  next();
};

// Middleware para verificar rol de admin
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado: se requiere rol de administrador' });
  }
  next();
};

// Limpiar rate limit store cada hora
setInterval(() => {
  rateLimitStore.clear();
  console.log('🧹 Rate limit store limpiado');
}, 60 * 60 * 1000);

module.exports = {
  authenticateToken,
  rateLimiter,
  requireAdmin
};