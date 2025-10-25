// mfa.js - Multi-Factor Authentication con TOTP
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt'); // Ya lo tienes importado en auth.js
/**
 * Genera un secreto para MFA y QR code
 * @param {string} email - Email del usuario
 * @returns {Promise<{secret: string, qrCode: string}>}
 */
async function generateMFASecret(email) {
  // Generar secreto
  const secret = speakeasy.generateSecret({
    name: `Aplicación Segura UMG (${email})`,
    issuer: 'UMG Seguridad',
    length: 32
  });

  // Generar QR code como Data URL
  const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url);

  return {
    secret: secret.base32, // Este se guarda en la BD
    qrCode: qrCodeDataURL, // Este se muestra al usuario
    otpauthUrl: secret.otpauth_url
  };
}

/**
 * Verifica un código TOTP
 * @param {string} token - Código de 6 dígitos ingresado por el usuario
 * @param {string} secret - Secreto MFA del usuario (de la BD)
 * @returns {boolean} - true si el código es válido
 */
function verifyMFAToken(token, secret) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2 // Permite 2 periodos de 30s antes/después (tolerancia de 1 min)
  });
}

/**
 * Genera código de backup (emergencia)
 * @returns {string} - Código de 16 caracteres
 */
function generateBackupCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Sin caracteres confusos
  let code = '';
  for (let i = 0; i < 16; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
    if ((i + 1) % 4 === 0 && i < 15) code += '-'; // Formato: XXXX-XXXX-XXXX-XXXX
  }
  return code;
}
/**
 * Genera múltiples códigos de backup hasheados
 * @param {number} count - Cantidad de códigos a generar (default: 10)
 * @returns {Promise<{plain: string[], hashed: string[]}>}
 */
async function generateBackupCodes(count = 10) {
  const codes = [];
  const hashed = [];
  
  for (let i = 0; i < count; i++) {
    const code = generateBackupCode(); // Usa la función que ya tienes
    codes.push(code);
    // Hashear código (igual que contraseñas)
    const hash = await bcrypt.hash(code, 10);
    hashed.push(hash);
  }
  
  return {
    plain: codes,    // Mostrar al usuario UNA VEZ
    hashed: hashed   // Guardar en BD
  };
}

/**
 * Verifica un código de backup y lo consume (elimina)
 * @param {string} code - Código ingresado por el usuario
 * @param {string[]} hashedCodes - Array de códigos hasheados de la BD
 * @returns {Promise<{valid: boolean, remainingCodes: string[]}>}
 */
async function verifyBackupCode(code, hashedCodes) {
  if (!hashedCodes || hashedCodes.length === 0) {
    return { valid: false, remainingCodes: [] };
  }

  // Buscar código que coincida
  for (let i = 0; i < hashedCodes.length; i++) {
    const match = await bcrypt.compare(code, hashedCodes[i]);
    if (match) {
      // Código válido - eliminarlo (consumir)
      const remaining = hashedCodes.filter((_, index) => index !== i);
      return { valid: true, remainingCodes: remaining };
    }
  }

  return { valid: false, remainingCodes: hashedCodes };
}
module.exports = {
  generateMFASecret,
  verifyMFAToken,
  generateBackupCode,
  generateBackupCodes,    // ← NUEVO
  verifyBackupCode        // ← NUEVO
};