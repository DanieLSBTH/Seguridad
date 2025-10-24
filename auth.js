const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const db = require('./db');
const { authenticateToken, rateLimiter } = require('./middleware');
const alerts = require('./alerts'); // ← AGREGAR ESTA LÍNEA
const mfa = require('./mfa'); // ← Agregar al inicio con los otros requires
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
// LOGIN de usuario (CON MFA)
router.post('/login', rateLimiter, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, mfaToken } = req.body; // ← Agregar mfaToken

    // Buscar usuario
    const result = await db.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      console.log(`⚠️ Intento de login fallido: ${email} - Usuario no existe`);
      await alerts.loginAttemptsFailed(email, req.ip);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = result.rows[0];

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      console.log(`⚠️ Intento de login fallido: ${email} - Contraseña incorrecta`);
      await alerts.loginAttemptsFailed(email, req.ip);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // ✅ NUEVA LÓGICA: Verificar si tiene MFA habilitado
    if (user.mfa_enabled) {
      // Si tiene MFA pero no envió el código
      if (!mfaToken) {
        return res.status(206).json({ 
          message: 'MFA requerido',
          mfa_required: true,
          instructions: 'Ingresa el código de 6 dígitos de tu Google Authenticator'
        });
      }

      // Verificar código MFA
      const mfaValid = mfa.verifyMFAToken(mfaToken, user.mfa_secret);

      if (!mfaValid) {
        console.log(`⚠️ Código MFA incorrecto: ${email}`);
        return res.status(401).json({ error: 'Código MFA incorrecto' });
      }

      console.log(`✅ Login con MFA exitoso: ${email}`);
    }

    // Actualizar último login
    await db.query(
      'UPDATE usuarios SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Generar JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, rol: user.rol },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    console.log(`✅ Login exitoso: ${email} - ${new Date().toISOString()}`);

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        email: user.email,
        nombre: user.nombre,
        rol: user.rol,
        mfa_enabled: user.mfa_enabled // ← Informar si tiene MFA
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

// HABILITAR MFA: Generar QR code
router.post('/mfa/setup', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Verificar si ya tiene MFA habilitado
    const userCheck = await db.query(
      'SELECT mfa_enabled FROM usuarios WHERE id = $1',
      [userId]
    );

    if (userCheck.rows[0].mfa_enabled) {
      return res.status(400).json({ 
        error: 'MFA ya está habilitado. Desactívalo primero si quieres regenerar.' 
      });
    }

    // Generar secreto y QR
    const { secret, qrCode } = await mfa.generateMFASecret(req.user.email);

    // Guardar secreto (pero NO habilitar MFA todavía)
    await db.query(
      'UPDATE usuarios SET mfa_secret = $1 WHERE id = $2',
      [secret, userId]
    );

    console.log(`📱 QR code generado para MFA: ${req.user.email}`);

    res.json({
      message: 'Escanea este QR code con Google Authenticator',
      qrCode: qrCode,
      secret: secret, // Para configuración manual
      instructions: [
        '1. Abre Google Authenticator en tu teléfono',
        '2. Toca el botón + (agregar cuenta)',
        '3. Escanea este QR code',
        '4. Ingresa el código de 6 dígitos en /mfa/verify para activar'
      ]
    });

  } catch (error) {
    console.error('Error configurando MFA:', error);
    res.status(500).json({ error: 'Error al configurar MFA' });
  }
});

// VERIFICAR Y ACTIVAR MFA
router.post('/mfa/verify', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.userId;

    if (!token || token.length !== 6) {
      return res.status(400).json({ error: 'Código inválido. Debe tener 6 dígitos.' });
    }

    // Obtener secreto
    const result = await db.query(
      'SELECT mfa_secret, mfa_enabled FROM usuarios WHERE id = $1',
      [userId]
    );

    if (!result.rows[0].mfa_secret) {
      return res.status(400).json({ 
        error: 'Primero debes generar un QR code en /mfa/setup' 
      });
    }

    // Verificar código
    const isValid = mfa.verifyMFAToken(token, result.rows[0].mfa_secret);

    if (!isValid) {
      console.log(`⚠️ Código MFA inválido para ${req.user.email}`);
      return res.status(401).json({ error: 'Código incorrecto' });
    }

    // HABILITAR MFA
    await db.query(
      'UPDATE usuarios SET mfa_enabled = true WHERE id = $1',
      [userId]
    );

    console.log(`✅ MFA habilitado para: ${req.user.email}`);

    res.json({
      message: '¡MFA activado exitosamente!',
      mfa_enabled: true
    });

  } catch (error) {
    console.error('Error verificando MFA:', error);
    res.status(500).json({ error: 'Error al verificar MFA' });
  }
});

// DESACTIVAR MFA
router.post('/mfa/disable', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user.userId;

    // Verificar contraseña actual por seguridad
    const result = await db.query(
      'SELECT password_hash FROM usuarios WHERE id = $1',
      [userId]
    );

    const validPassword = await bcrypt.compare(password, result.rows[0].password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    // Desactivar MFA
    await db.query(
      'UPDATE usuarios SET mfa_enabled = false, mfa_secret = NULL WHERE id = $1',
      [userId]
    );

    console.log(`⚠️ MFA deshabilitado para: ${req.user.email}`);

    res.json({ message: 'MFA desactivado' });

  } catch (error) {
    console.error('Error deshabilitando MFA:', error);
    res.status(500).json({ error: 'Error al deshabilitar MFA' });
  }
});


module.exports = router;