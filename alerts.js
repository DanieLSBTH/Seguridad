// alerts.js - Sistema de alertas de seguridad con SendGrid
const sgMail = require('@sendgrid/mail');

// Configurar SendGrid
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log(' SendGrid API Key configurada');
} else {
  console.log(' SendGrid API Key NO encontrada en .env');
}

// Función para obtener el color según la severidad
function getSeverityColor(severity) {
  const colors = {
    'CRÍTICA': '#d13438',
    'ALTA': '#ea4300',
    'MEDIA': '#ffb900',
    'BAJA': '#00b7c3',
    'INFO': '#0078d4'
  };
  return colors[severity] || '#605e5c';
}

// Función para obtener el icono según el tipo de alerta
function getAlertIcon(type) {
  if (type.includes('Login')) return '⚠';
  if (type.includes('SQL')) return '⚠';
  if (type.includes('Rate Limit')) return '⚠';
  if (type.includes('Acceso')) return '⚠';
  if (type.includes('Usuario')) return 'ℹ';
  return '⚠';
}

async function sendAlert(type, details) {
  // Verificar configuración
  if (!process.env.SENDGRID_API_KEY) {
    console.log(' SENDGRID_API_KEY no configurada');
    return;
  }
  
  if (!process.env.ALERT_EMAIL) {
    console.log(' ALERT_EMAIL no configurada');
    return;
  }

  if (!process.env.ALERT_FROM_EMAIL) {
    console.log(' ALERT_FROM_EMAIL no configurada');
    return;
  }

  console.log(' Intentando enviar email...');
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
    subject: `[${details.severity}] ${type}`,
    text: `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ALERTA DE SEGURIDAD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${alertIcon} TIPO: ${type}
 SEVERIDAD: ${details.severity}
 FECHA: ${timestamp}
 IP: ${details.ip || 'Desconocida'}
${details.email ? ` EMAIL: ${details.email}` : ''}
${details.endpoint ? ` ENDPOINT: ${details.endpoint}` : ''}
${details.userId ? ` USER ID: ${details.userId}` : ''}
${details.resource ? ` RECURSO: ${details.resource}` : ''}

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
    body {
      margin: 0;
      padding: 0;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f3f2f1;
      -webkit-font-smoothing: antialiased;
    }
    .email-wrapper {
      max-width: 600px;
      margin: 40px auto;
      background-color: #ffffff;
    }
    .header {
      padding: 32px 40px 24px 40px;
      border-bottom: 1px solid #edebe9;
    }
    .severity-label {
      display: inline-block;
      color: ${severityColor};
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 12px;
    }
    .title {
      font-size: 24px;
      font-weight: 600;
      color: #201f1e;
      margin: 0 0 8px 0;
      line-height: 1.3;
    }
    .subtitle {
      font-size: 15px;
      color: #605e5c;
      margin: 0;
      line-height: 1.5;
    }
    .content {
      padding: 32px 40px;
    }
    .info-section {
      margin-bottom: 32px;
    }
    .section-label {
      font-size: 13px;
      font-weight: 600;
      color: #323130;
      margin-bottom: 12px;
    }
    .info-item {
      display: flex;
      padding: 10px 0;
      border-bottom: 1px solid #f3f2f1;
    }
    .info-item:last-child {
      border-bottom: none;
    }
    .info-key {
      flex: 0 0 140px;
      font-size: 14px;
      color: #605e5c;
    }
    .info-value {
      flex: 1;
      font-size: 14px;
      color: #201f1e;
      word-break: break-word;
    }
    .alert-box {
      background-color: #fef6f6;
      border-left: 4px solid ${severityColor};
      padding: 16px 20px;
      margin: 24px 0;
    }
    .alert-box-title {
      font-size: 14px;
      font-weight: 600;
      color: #323130;
      margin: 0 0 8px 0;
    }
    .alert-box-text {
      font-size: 14px;
      color: #323130;
      margin: 0;
      line-height: 1.6;
    }
    .button {
      display: inline-block;
      background-color: ${severityColor};
      color: #ffffff;
      text-decoration: none;
      padding: 10px 24px;
      font-size: 14px;
      font-weight: 600;
      border-radius: 2px;
      margin: 8px 0 24px 0;
    }
    .technical-section {
      background-color: #faf9f8;
      padding: 16px 20px;
      margin-top: 24px;
      border-radius: 2px;
    }
    .technical-title {
      font-size: 13px;
      font-weight: 600;
      color: #323130;
      margin: 0 0 12px 0;
    }
    .technical-content {
      font-family: 'Courier New', Courier, monospace;
      font-size: 12px;
      color: #323130;
      white-space: pre-wrap;
      word-wrap: break-word;
      margin: 0;
      line-height: 1.6;
    }
    .footer {
      padding: 24px 40px 32px 40px;
      border-top: 1px solid #edebe9;
      text-align: center;
    }
    .footer-text {
      font-size: 12px;
      color: #605e5c;
      line-height: 1.6;
      margin: 0;
    }
    .footer-link {
      color: #0078d4;
      text-decoration: none;
    }
    @media only screen and (max-width: 600px) {
      .email-wrapper {
        margin: 0;
      }
      .header, .content, .footer {
        padding-left: 24px;
        padding-right: 24px;
      }
      .info-item {
        flex-direction: column;
      }
      .info-key {
        margin-bottom: 4px;
      }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <!-- Header -->
    <div class="header">
      <div class="severity-label">${details.severity}</div>
      <h1 class="title">${type}</h1>
      <p class="subtitle">Detectamos una actividad inusual en el sistema de seguridad</p>
    </div>

    <!-- Content -->
    <div class="content">
      <!-- Alert Information -->
      <div class="info-section">
        <div class="section-label">Detalles del evento</div>
        <div class="info-item">
          <div class="info-key">Fecha </div>
          <div class="info-value">${timestamp}</div>
        </div>
        <div class="info-item">
          <div class="info-key">Dirección IP</div>
          <div class="info-value">${details.ip || 'No disponible'}</div>
        </div>
        ${details.email ? `
        <div class="info-item">
          <div class="info-key">Email </div>
          <div class="info-value">${details.email}</div>
        </div>
        ` : ''}
        ${details.endpoint ? `
        <div class="info-item">
          <div class="info-key">Endpoint</div>
          <div class="info-value">${details.endpoint}</div>
        </div>
        ` : ''}
        ${details.userId ? `
        <div class="info-item">
          <div class="info-key">ID de Usuario</div>
          <div class="info-value">${details.userId}</div>
        </div>
        ` : ''}
        ${details.resource ? `
        <div class="info-item">
          <div class="info-key">Recurso</div>
          <div class="info-value">${details.resource}</div>
        </div>
        ` : ''}
        ${details.attempts ? `
        <div class="info-item">
          <div class="info-key">Intentos</div>
          <div class="info-value">${details.attempts}</div>
        </div>
        ` : ''}
        ${details.payload ? `
        <div class="info-item">
          <div class="info-key">Payload detectado</div>
          <div class="info-value">${details.payload}</div>
        </div>
        ` : ''}
      </div>

      <!-- Action Required -->
      <div class="alert-box">
        <p class="alert-box-title">Acción requerida</p>
        <p class="alert-box-text">${details.action}</p>
      </div>

      <!-- Technical Details -->
      <div class="technical-section">
        <p class="technical-title">Información técnica</p>
        <pre class="technical-content">${JSON.stringify(details, null, 2)}</pre>
      </div>
    </div>

    <!-- Footer -->
    <div class="footer">
      <p class="footer-text">
        <strong>Sistema de Seguridad UMG</strong><br>
        Maestría en Seguridad Informática<br>
        Universidad Mariano Gálvez de Guatemala<br><br>
        Este es un mensaje automático del sistema de monitoreo de seguridad.
      </p>
    </div>
  </div>
</body>
</html>
    `,
  };

  try {
    await sgMail.send(msg);
    console.log(` Alerta enviada exitosamente: ${type}`);
  } catch (error) {
    console.error(' Error enviando alerta:', error.message);
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