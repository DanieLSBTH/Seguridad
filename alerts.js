// alerts.js - Sistema de alertas de seguridad con SendGrid
const sgMail = require('@sendgrid/mail');

// Configurar SendGrid
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log('✅ SendGrid API Key configurada');
} else {
  console.log('⚠️ SendGrid API Key NO encontrada en .env');
}

// Función para obtener el color según la severidad
function getSeverityColor(severity) {
  const colors = {
    'CRÍTICA': '#dc3545',
    'ALTA': '#fd7e14',
    'MEDIA': '#ffc107',
    'BAJA': '#0dcaf0',
    'INFO': '#0d6efd'
  };
  return colors[severity] || '#6c757d';
}

// Función para obtener el icono según el tipo de alerta
function getAlertIcon(type) {
  if (type.includes('Login')) return '🔐';
  if (type.includes('SQL')) return '💉';
  if (type.includes('Rate Limit')) return '⏱️';
  if (type.includes('Acceso')) return '🚫';
  if (type.includes('Usuario')) return '👤';
  return '🚨';
}

async function sendAlert(type, details) {
  // Verificar configuración
  if (!process.env.SENDGRID_API_KEY) {
    console.log('⚠️ SENDGRID_API_KEY no configurada');
    return;
  }
  
  if (!process.env.ALERT_EMAIL) {
    console.log('⚠️ ALERT_EMAIL no configurada');
    return;
  }

  if (!process.env.ALERT_FROM_EMAIL) {
    console.log('⚠️ ALERT_FROM_EMAIL no configurada');
    return;
  }

  console.log('📧 Intentando enviar email...');
  console.log('  To:', process.env.ALERT_EMAIL);
  console.log('  From:', process.env.ALERT_FROM_EMAIL);
  console.log('  Type:', type);

  const severityColor = getSeverityColor(details.severity);
  const alertIcon = getAlertIcon(type);
  const timestamp = new Date().toLocaleString('es-GT', { 
    timeZone: 'America/Guatemala',
    dateStyle: 'full',
    timeStyle: 'long'
  });

  const msg = {
    to: process.env.ALERT_EMAIL,
    from: process.env.ALERT_FROM_EMAIL,
    subject: `${alertIcon} [${details.severity}] ${type}`,
    text: `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ALERTA DE SEGURIDAD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${alertIcon} TIPO: ${type}
🎯 SEVERIDAD: ${details.severity}
📅 FECHA: ${timestamp}
🌐 IP: ${details.ip || 'Desconocida'}
${details.email ? `📧 EMAIL: ${details.email}` : ''}
${details.endpoint ? `🔗 ENDPOINT: ${details.endpoint}` : ''}
${details.userId ? `👤 USER ID: ${details.userId}` : ''}
${details.resource ? `📁 RECURSO: ${details.resource}` : ''}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ACCIÓN REQUERIDA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${details.action}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DETALLES TÉCNICOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${JSON.stringify(details, null, 2)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sistema de Seguridad UMG
Maestría en Seguridad Informática
Universidad Mariano Gálvez de Guatemala
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `,
    html: `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6; 
      background: #f4f6f9;
      padding: 20px;
    }
    .email-wrapper {
      max-width: 650px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 40px rgba(0,0,0,0.1);
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px 30px;
      text-align: center;
    }
    .header h1 {
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 10px;
      text-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .header .subtitle {
      font-size: 14px;
      opacity: 0.95;
      font-weight: 300;
    }
    .alert-badge {
      display: inline-block;
      background: ${severityColor};
      color: white;
      padding: 12px 24px;
      border-radius: 25px;
      font-weight: 700;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin: 30px auto;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .content {
      padding: 40px 30px;
    }
    .alert-title {
      font-size: 24px;
      color: #2c3e50;
      margin-bottom: 25px;
      padding-bottom: 15px;
      border-bottom: 3px solid ${severityColor};
      font-weight: 600;
    }
    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .info-card {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid ${severityColor};
      transition: transform 0.2s;
    }
    .info-card:hover {
      transform: translateX(5px);
    }
    .info-label {
      font-size: 12px;
      color: #6c757d;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 5px;
    }
    .info-value {
      font-size: 16px;
      color: #2c3e50;
      font-weight: 500;
      word-break: break-all;
    }
    .action-box {
      background: linear-gradient(135deg, #fff5e6 0%, #ffe9cc 100%);
      border: 2px solid #ff9800;
      border-radius: 8px;
      padding: 25px;
      margin: 30px 0;
    }
    .action-box h3 {
      color: #e65100;
      font-size: 18px;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .action-box p {
      color: #5d4037;
      font-size: 15px;
      line-height: 1.6;
    }
    .details-section {
      background: #f8f9fa;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
    }
    .details-section h3 {
      color: #495057;
      font-size: 16px;
      margin-bottom: 15px;
      font-weight: 600;
    }
    .details-code {
      background: #2d3748;
      color: #e2e8f0;
      padding: 20px;
      border-radius: 6px;
      font-family: 'Courier New', monospace;
      font-size: 13px;
      overflow-x: auto;
      line-height: 1.5;
    }
    .footer {
      background: #2c3e50;
      color: #ecf0f1;
      padding: 30px;
      text-align: center;
    }
    .footer h4 {
      color: #3498db;
      font-size: 16px;
      margin-bottom: 10px;
    }
    .footer p {
      font-size: 13px;
      opacity: 0.9;
      margin: 5px 0;
    }
    .footer-logo {
      font-size: 32px;
      margin-bottom: 10px;
    }
    @media only screen and (max-width: 600px) {
      .email-wrapper { border-radius: 0; }
      .header { padding: 30px 20px; }
      .content { padding: 25px 20px; }
      .info-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <!-- Header -->
    <div class="header">
      <h1>${alertIcon} ALERTA DE SEGURIDAD</h1>
      <p class="subtitle">Sistema de Monitoreo y Detección de Amenazas</p>
      <div class="alert-badge">${details.severity}</div>
    </div>

    <!-- Content -->
    <div class="content">
      <div class="alert-title">
        ${alertIcon} ${type}
      </div>

      <!-- Info Grid -->
      <div class="info-grid">
        <div class="info-card">
          <div class="info-label">📅 Fecha y Hora</div>
          <div class="info-value">${timestamp}</div>
        </div>
        
        <div class="info-card">
          <div class="info-label">🌐 Dirección IP</div>
          <div class="info-value">${details.ip || 'No disponible'}</div>
        </div>
        
        ${details.email ? `
        <div class="info-card">
          <div class="info-label">📧 Email</div>
          <div class="info-value">${details.email}</div>
        </div>
        ` : ''}
        
        ${details.endpoint ? `
        <div class="info-card">
          <div class="info-label">🔗 Endpoint</div>
          <div class="info-value">${details.endpoint}</div>
        </div>
        ` : ''}
        
        ${details.userId ? `
        <div class="info-card">
          <div class="info-label">👤 ID de Usuario</div>
          <div class="info-value">${details.userId}</div>
        </div>
        ` : ''}
        
        ${details.resource ? `
        <div class="info-card">
          <div class="info-label">📁 Recurso</div>
          <div class="info-value">${details.resource}</div>
        </div>
        ` : ''}
        
        ${details.attempts ? `
        <div class="info-card">
          <div class="info-label">🔄 Intentos</div>
          <div class="info-value">${details.attempts}</div>
        </div>
        ` : ''}
      </div>

      <!-- Action Box -->
      <div class="action-box">
        <h3>⚠️ Acción Requerida</h3>
        <p>${details.action}</p>
      </div>

      <!-- Details Section -->
      <div class="details-section">
        <h3>🔍 Información Técnica Detallada</h3>
        <div class="details-code">${JSON.stringify(details, null, 2)}</div>
      </div>
    </div>

    <!-- Footer -->
    <div class="footer">
      <div class="footer-logo">🛡️</div>
      <h4>Sistema de Seguridad UMG</h4>
      <p>Maestría en Seguridad Informática</p>
      <p>Universidad Mariano Gálvez de Guatemala</p>
      <p style="margin-top: 15px; font-size: 12px; opacity: 0.7;">
        Este es un correo automático generado por el sistema de monitoreo de seguridad.
      </p>
    </div>
  </div>
</body>
</html>
    `,
  };

  try {
    await sgMail.send(msg);
    console.log(`✅ Alerta enviada exitosamente: ${type}`);
  } catch (error) {
    console.error('❌ Error enviando alerta:', error.message);
    if (error.response) {
      console.error('Código:', error.response.statusCode);
      console.error('Body:', error.response.body);
    }
  }
}

module.exports = {
  // Múltiples intentos de login fallidos
  loginAttemptsFailed: async (email, ip, attempts = 1) => {
    await sendAlert('Múltiples Intentos de Login Fallidos', {
      email,
      ip,
      attempts,
      action: 'Se ha detectado un posible ataque de fuerza bruta. Revise los registros de acceso y considere bloquear temporalmente esta dirección IP si el comportamiento persiste.',
      severity: 'ALTA',
      timestamp: new Date().toISOString()
    });
  },

  // Rate limiting excedido
  rateLimitExceeded: async (ip, endpoint) => {
    await sendAlert('Límite de Solicitudes Excedido', {
      ip,
      endpoint,
      action: 'Un usuario ha excedido el límite de solicitudes permitidas. El acceso ha sido temporalmente restringido. Verifique si es actividad legítima o un posible ataque.',
      severity: 'MEDIA',
      timestamp: new Date().toISOString()
    });
  },

  // Posible SQL Injection
  sqlInjectionAttempt: async (email, ip, payload) => {
    await sendAlert('Intento de Inyección SQL Detectado', {
      email,
      ip,
      payload: payload.substring(0, 100),
      action: 'ATENCIÓN: Se han detectado caracteres SQL sospechosos en una solicitud. La petición fue bloqueada automáticamente. Investigue inmediatamente la fuente de este ataque.',
      severity: 'CRÍTICA',
      timestamp: new Date().toISOString()
    });
  },

  // Acceso no autorizado
  unauthorizedAccess: async (userId, resource, ip) => {
    await sendAlert('Intento de Acceso No Autorizado', {
      userId,
      resource,
      ip,
      action: 'Un usuario intentó acceder a un recurso sin los permisos necesarios. Verifique si es un error de configuración o un intento malicioso de escalada de privilegios.',
      severity: 'ALTA',
      timestamp: new Date().toISOString()
    });
  },

  // Usuario nuevo registrado
  newUserRegistered: async (email, ip) => {
    await sendAlert('Nuevo Usuario Registrado', {
      email,
      ip,
      action: 'Un nuevo usuario se ha registrado exitosamente en la aplicación. Esta es una notificación informativa para monitoreo de actividad.',
      severity: 'INFO',
      timestamp: new Date().toISOString()
    });
  }
};