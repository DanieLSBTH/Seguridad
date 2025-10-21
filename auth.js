const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const db = require('./db');
const { authenticateToken, rateLimiter } = require('./middleware');
const alerts = require('./alerts'); // ← AGREGAR ESTA LÍNEA

const router = express.Router();
const SALT_ROUNDS = 12;

// Validaciones comunes
const registerValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Contraseña debe contener mayúsculas, minúsculas y números'),
  body('nombre').trim().isLength({ min: 2 }).withMessage('Nombre muy corto'),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
];

// REGISTRO de usuario
router.post('/register', rateLimiter, registerValidation, async (req, res) => {
  try {
    // Verificar errores de validación
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, nombre } = req.body;

    // Verificar si el usuario ya existe (consulta parametrizada)
    const existingUser = await db.query(
      'SELECT id FROM usuarios WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        error: 'El email ya está registrado' 
      });
    }

    // Hashear contraseña con bcrypt + salt
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insertar usuario (consulta parametrizada previene SQL injection)
    const result = await db.query(
      'INSERT INTO usuarios (email, password_hash, nombre, rol) VALUES ($1, $2, $3, $4) RETURNING id, email, nombre, rol, created_at',
      [email, hashedPassword, nombre, 'user']
    );

    const user = result.rows[0];

    // Log de seguridad
    console.log(` Nuevo usuario registrado: ${email} - ${new Date().toISOString()}`);
    await alerts.newUserRegistered(email, req.ip); // ← AGREGAR ESTA LÍNEA

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: {
        id: user.id,
        email: user.email,
        nombre: user.nombre,
        rol: user.rol
      }
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// LOGIN de usuario
router.post('/login', rateLimiter, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Buscar usuario (consulta parametrizada)
    const result = await db.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      // Log de intento fallido
      console.log(` Intento de login fallido: ${email} - Usuario no existe`);
      await alerts.loginAttemptsFailed(email, req.ip); // ← AGREGAR ESTA LÍNEA
  
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = result.rows[0];

    // Verificar contraseña con bcrypt
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      console.log(` Intento de login fallido: ${email} - Contraseña incorrecta`);
       // Enviar alerta
      await alerts.loginAttemptsFailed(email, req.ip); // ← AGREGAR ESTA LÍNEA
  
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Actualizar último login
    await db.query(
      'UPDATE usuarios SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Generar JWT (expira en 1 hora)
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        rol: user.rol 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    console.log(` Login exitoso: ${email} - ${new Date().toISOString()}`);

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        email: user.email,
        nombre: user.nombre,
        rol: user.rol
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// RUTA PROTEGIDA (ejemplo)
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    // req.user viene del middleware authenticateToken
    const result = await db.query(
      'SELECT id, email, nombre, rol, created_at, last_login FROM usuarios WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ user: result.rows[0] });

  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

// LISTAR usuarios (solo admin)
router.get('/users', authenticateToken, async (req, res) => {
  try {
    // Verificar que sea admin
    if (req.user.rol !== 'admin') {
      return res.status(403).json({ error: 'Acceso denegado' });
    }

    const result = await db.query(
      'SELECT id, email, nombre, rol, created_at, last_login FROM usuarios ORDER BY created_at DESC'
    );

    res.json({ users: result.rows });

  } catch (error) {
    console.error('Error listando usuarios:', error);
    res.status(500).json({ error: 'Error al listar usuarios' });
  }
});

module.exports = router;