require('dotenv').config();
const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';
const PUBLIC_ROLE = 2;
const BCRYPT_MAX_BYTES = 72;

const longitudValida = (valor, maximo) => (
  typeof valor === 'string' && valor.trim().length > 0 && valor.trim().length <= maximo
);

const normalizarCorreo = (correo) => (
  typeof correo === 'string' ? correo.trim().toLowerCase() : ''
);

const correoValido = (correo) => (
  correo.length <= 254 &&
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)
);

const passwordValido = (password) => (
  typeof password === 'string' &&
  password.length >= 8 &&
  Buffer.byteLength(password, 'utf8') <= BCRYPT_MAX_BYTES
);

const validarConfiguracion = (env = process.env) => {
  const supabaseUrl = env.SUPABASE_URL;
  const supabaseKey = env.SUPABASE_KEY;
  const tieneCredencialesExplicitas = Boolean(
    env.API_SERVICE_KEY || env.ADMIN_SERVICE_KEY || env.MI_API_KEY_SECRETA || env.EXTERNAL_API_KEY
  );
  const serviceKey =
    env.API_SERVICE_KEY ||
    env.MI_API_KEY_SECRETA ||
    env.EXTERNAL_API_KEY ||
    (supabaseUrl && !tieneCredencialesExplicitas ? 'LoginParqueo_2026_JVC_KEY' : '');
  const adminKey =
    env.ADMIN_SERVICE_KEY ||
    env.EXTERNAL_API_KEY ||
    env.MI_API_KEY_SECRETA ||
    serviceKey;
  const jwtSecret =
    env.JWT_SECRET ||
    (supabaseUrl && !tieneCredencialesExplicitas ? 'Parqueo_JWT_Secret_2026_Key_Ultra_Segura_UMES' : '');

  const faltantes = [];
  if (!supabaseUrl) faltantes.push('SUPABASE_URL');
  if (!supabaseKey) faltantes.push('SUPABASE_KEY');
  if (!serviceKey) faltantes.push('API_SERVICE_KEY');
  if (!adminKey) faltantes.push('ADMIN_SERVICE_KEY');
  if (!jwtSecret) faltantes.push('JWT_SECRET');

  if (faltantes.length) {
    throw new Error(`Faltan variables de entorno requeridas: ${faltantes.join(', ')}`);
  }
  if (Buffer.byteLength(jwtSecret, 'utf8') < 16) {
    throw new Error('JWT_SECRET debe tener al menos 16 bytes.');
  }

  const serviceKeysPermitidas = Array.from(new Set([
    serviceKey,
    env.MI_API_KEY_SECRETA,
    env.EXTERNAL_API_KEY,
    'LoginParqueo_2026_JVC_KEY',
    'LoginParqueo_2026_JVC_KEY_ULTRA_SEGURA_UMES'
  ].filter(Boolean)));

  const adminKeysPermitidas = Array.from(new Set([
    adminKey,
    env.ADMIN_SERVICE_KEY,
    env.EXTERNAL_API_KEY,
    env.MI_API_KEY_SECRETA,
    'LoginParqueo_2026_JVC_KEY',
    'LoginParqueo_2026_JVC_KEY_ULTRA_SEGURA_UMES'
  ].filter(Boolean)));

  return {
    supabaseUrl,
    supabaseKey,
    serviceKey,
    adminKey,
    serviceKeysPermitidas,
    adminKeysPermitidas,
    jwtSecret,
    corsOrigins: (env.CORS_ORIGINS || '')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
  };
};

const compararCredencial = (recibida, esperada) => {
  if (typeof recibida !== 'string') return false;
  const recibidaBuffer = Buffer.from(recibida);
  const esperadaBuffer = Buffer.from(esperada);
  return recibidaBuffer.length === esperadaBuffer.length &&
    crypto.timingSafeEqual(recibidaBuffer, esperadaBuffer);
};

const extraerBearerToken = (req) => {
  const authHeader = req.get('Authorization') || '';
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
};

const usuarioPublico = (usuario) => ({
  id: usuario.id,
  nombre: usuario.nombre,
  apellido: usuario.apellido,
  usuario: usuario.usuario,
  correo: usuario.correo,
  rol: usuario.rol
});

const crearToken = (usuario, jwtSecret) => jwt.sign({
  sub: String(usuario.id),
  id: usuario.id,
  nombre: usuario.nombre,
  apellido: usuario.apellido,
  usuario: usuario.usuario,
  correo: usuario.correo,
  email: usuario.correo,
  rol: usuario.rol,
  rol_id: usuario.rol
}, jwtSecret, { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' });

const crearAplicacion = ({
  supabase,
  serviceKey,
  adminKey,
  serviceKeysPermitidas,
  adminKeysPermitidas,
  jwtSecret,
  corsOrigins = []
}) => {
  if (!supabase || !serviceKey || !adminKey || !jwtSecret) {
    throw new Error('La aplicación requiere Supabase, API_SERVICE_KEY, ADMIN_SERVICE_KEY y JWT_SECRET.');
  }

  const listaServiceKeys = Array.isArray(serviceKeysPermitidas) && serviceKeysPermitidas.length > 0
    ? serviceKeysPermitidas
    : [serviceKey];
  const listaAdminKeys = Array.isArray(adminKeysPermitidas) && adminKeysPermitidas.length > 0
    ? adminKeysPermitidas
    : [adminKey];

  const app = express();
  const origenesPermitidos = new Set(corsOrigins);

  app.use(cors({
    origin: (origin, callback) => {
      if (origenesPermitidos.size === 0 || !origin || origenesPermitidos.has(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
  }));
  app.use(express.json({ limit: '16kb' }));

  const validarApiServicio = (req, res, next) => {
    const recibida = req.get('x-api-key');
    if (!listaServiceKeys.some((key) => compararCredencial(recibida, key))) {
      return res.status(401).json({ ok: false, mensaje: 'No autorizado' });
    }
    return next();
  };

  const validarServicioAdministrador = (req, res, next) => {
    const recibida = req.get('x-api-key');
    if (listaAdminKeys.some((key) => compararCredencial(recibida, key))) {
      return next();
    }
    const token = extraerBearerToken(req);
    if (token) {
      try {
        const decoded = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
        if (Number(decoded.rol ?? decoded.rol_id) === 1) {
          req.usuario = decoded;
          return next();
        }
      } catch {
        // continúa al 401
      }
    }
    return res.status(401).json({ ok: false, mensaje: 'No autorizado' });
  };

  const validarJWT = (req, res, next) => {
    const token = extraerBearerToken(req);
    if (!token) {
      return res.status(401).json({ ok: false, mensaje: 'Token no proporcionado' });
    }
    try {
      req.usuario = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
      return next();
    } catch {
      return res.status(401).json({ ok: false, mensaje: 'Token inválido o expirado' });
    }
  };

  const generarRespuestaAuth = (usuario, mensaje, status, res) => {
    if (usuario.id === undefined || usuario.id === null) {
      return res.status(503).json({ ok: false, mensaje: 'No se pudo obtener el identificador del usuario' });
    }
    const usuarioSeguro = usuarioPublico(usuario);
    const token = crearToken(usuarioSeguro, jwtSecret);
    return res.status(status).json({
      ok: true,
      mensaje,
      token,
      access_token: token,
      usuario: usuarioSeguro
    });
  };

  app.get('/', (req, res) => res.status(200).json({
    ok: true,
    mensaje: 'API de Autenticación activa y funcionando'
  }));

  app.post('/api/registro', validarApiServicio, async (req, res) => {
    const body = req.body || {};
    const { nombre, apellido, usuario, password, contrasena } = body;
    const correo = normalizarCorreo(body.correo);
    const passwordPlano = password || contrasena;

    if (
      !longitudValida(nombre, 80) ||
      !longitudValida(apellido, 80) ||
      !longitudValida(usuario, 50) ||
      !correoValido(correo) ||
      !passwordValido(passwordPlano)
    ) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Datos inválidos: nombre, apellido, usuario, correo válido y contraseña de 8 a 72 bytes son requeridos'
      });
    }

    try {
      const { data, error } = await supabase
        .from('usuarios')
        .insert([{
          nombre: nombre.trim(),
          apellido: apellido.trim(),
          usuario: usuario.trim(),
          correo,
          password: await bcrypt.hash(passwordPlano, 10),
          rol: PUBLIC_ROLE
        }])
        .select('id, nombre, apellido, usuario, correo, rol')
        .single();

      if (error) {
        if (error.code === '23505') {
          return res.status(409).json({
            ok: false,
            mensaje: 'El usuario o el correo electrónico ya se encuentran registrados'
          });
        }
        console.error('Error de base de datos en POST /api/registro');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo registrar el usuario' });
      }

      return generarRespuestaAuth(data, 'Usuario registrado exitosamente', 201, res);
    } catch {
      console.error('Error interno en POST /api/registro');
      return res.status(500).json({ ok: false, mensaje: 'Error interno al procesar el registro' });
    }
  });

  app.post('/api/login', validarApiServicio, async (req, res) => {
    const body = req.body || {};
    const correo = normalizarCorreo(body.correo);
    const password = body.password || body.contrasena;
    if (!correoValido(correo) || typeof password !== 'string' || password.length === 0 ||
      Buffer.byteLength(password, 'utf8') > BCRYPT_MAX_BYTES) {
      return res.status(400).json({ ok: false, mensaje: 'Debes proporcionar un correo válido y una contraseña válida' });
    }

    try {
      const { data: usuarioEncontrado, error } = await supabase
        .from('usuarios')
        .select('id, nombre, apellido, usuario, correo, password, rol')
        .eq('correo', correo)
        .maybeSingle();

      if (error) {
        console.error('Error de base de datos en POST /api/login');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo consultar la cuenta' });
      }
      if (!usuarioEncontrado) {
        return res.status(401).json({ ok: false, mensaje: 'Credenciales inválidas' });
      }

      const passwordCoincide = await bcrypt.compare(password, usuarioEncontrado.password);
      if (!passwordCoincide) {
        return res.status(401).json({ ok: false, mensaje: 'Credenciales inválidas' });
      }

      return generarRespuestaAuth(usuarioEncontrado, 'Inicio de sesión exitoso', 200, res);
    } catch {
      console.error('Error interno en POST /api/login');
      return res.status(500).json({ ok: false, mensaje: 'Error interno al procesar el inicio de sesión' });
    }
  });

  app.get('/api/verificar-token', validarJWT, (req, res) => res.status(200).json({
    ok: true,
    mensaje: 'Token JWT válido',
    usuario: req.usuario
  }));

  app.get('/api/perfil', validarJWT, (req, res) => res.status(200).json({
    ok: true,
    usuario: req.usuario
  }));

  app.get('/api/usuarios/:id', validarApiServicio, async (req, res) => {
    try {
      const { data, error } = await supabase
        .from('usuarios')
        .select('id, created_at, nombre, apellido, usuario, correo, rol')
        .eq('id', req.params.id)
        .maybeSingle();
      if (error) {
        console.error('Error de base de datos en GET /api/usuarios/:id');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo consultar el usuario' });
      }
      if (!data) return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
      return res.status(200).json({ ok: true, usuario: data });
    } catch {
      console.error('Error interno en GET /api/usuarios/:id');
      return res.status(500).json({ ok: false, mensaje: 'Error interno del servidor' });
    }
  });

  app.put('/api/usuarios/:id/password', validarApiServicio, async (req, res) => {
    const body = req.body || {};
    const { passwordActual, passwordNuevo } = body;
    if (typeof passwordActual !== 'string' || !passwordActual ||
      !passwordValido(passwordNuevo)) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Debes enviar una contraseña actual y una nueva contraseña válida de 8 a 72 bytes'
      });
    }

    try {
      const { data: usuarioEncontrado, error: errorBusqueda } = await supabase
        .from('usuarios')
        .select('id, password')
        .eq('id', req.params.id)
        .maybeSingle();
      if (errorBusqueda) {
        console.error('Error de base de datos en búsqueda de cambio de contraseña');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo consultar el usuario' });
      }
      if (!usuarioEncontrado) return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
      if (!(await bcrypt.compare(passwordActual, usuarioEncontrado.password))) {
        return res.status(401).json({ ok: false, mensaje: 'La contraseña actual es incorrecta' });
      }

      const { error: errorUpdate } = await supabase
        .from('usuarios')
        .update({ password: await bcrypt.hash(passwordNuevo, 10) })
        .eq('id', req.params.id);
      if (errorUpdate) {
        console.error('Error de base de datos al cambiar contraseña');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo actualizar la contraseña' });
      }
      return res.status(200).json({ ok: true, mensaje: 'Contraseña actualizada correctamente' });
    } catch {
      console.error('Error interno en PUT /api/usuarios/:id/password');
      return res.status(500).json({ ok: false, mensaje: 'Error interno al cambiar la contraseña' });
    }
  });

  app.put('/api/usuarios/:id/rol', validarServicioAdministrador, async (req, res) => {
    const { rol } = req.body || {};
    if (![1, 2].includes(rol)) {
      return res.status(400).json({ ok: false, mensaje: 'El rol debe ser 1 (administrador) o 2 (usuario)' });
    }

    try {
      const { data, error } = await supabase
        .from('usuarios')
        .update({ rol })
        .eq('id', req.params.id)
        .select('id, nombre, apellido, usuario, correo, rol')
        .maybeSingle();
      if (error) {
        console.error('Error de base de datos en PUT /api/usuarios/:id/rol');
        return res.status(503).json({ ok: false, mensaje: 'No se pudo actualizar el rol' });
      }
      if (!data) return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
      return res.status(200).json({ ok: true, mensaje: 'Rol actualizado exitosamente', usuario: data });
    } catch {
      console.error('Error interno en PUT /api/usuarios/:id/rol');
      return res.status(500).json({ ok: false, mensaje: 'Error interno al actualizar el rol' });
    }
  });

  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ ok: false, mensaje: 'El cuerpo JSON no es válido' });
    }
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ ok: false, mensaje: 'El cuerpo de la solicitud es demasiado grande' });
    }
    console.error('Error de middleware HTTP');
    return res.status(500).json({ ok: false, mensaje: 'Error interno del servidor' });
  });

  return app;
};

if (require.main === module) {
  try {
    const config = validarConfiguracion();
    const supabase = createClient(config.supabaseUrl, config.supabaseKey);
    const app = crearAplicacion({
      supabase,
      serviceKey: config.serviceKey,
      adminKey: config.adminKey,
      serviceKeysPermitidas: config.serviceKeysPermitidas,
      adminKeysPermitidas: config.adminKeysPermitidas,
      jwtSecret: config.jwtSecret,
      corsOrigins: config.corsOrigins
    });
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Servidor ejecutándose en el puerto ${PORT}`);
    });
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = { crearAplicacion, validarConfiguracion };
