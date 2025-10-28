// password-reset.js
const crypto = require('crypto');

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getResetExpiration() {
  return new Date(Date.now() + 3600000); // 1 hora
}

module.exports = {
  generateResetToken,
  getResetExpiration
};