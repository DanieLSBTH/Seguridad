// mfa.js - Multi-Factor Authentication con TOTP
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

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

module.exports = {
  generateMFASecret,
  verifyMFAToken,
  generateBackupCode
};