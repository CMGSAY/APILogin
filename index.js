require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization']
}));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const MI_API_KEY_SECRETA = process.env.MI_API_KEY_SECRETA;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('Error crítico: Faltan las variables SUPABASE_URL o SUPABASE_KEY en el archivo .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.get('/', (req, res) => {
  res.status(200).json({
    ok: true,
    mensaje: 'API de Autenticación activa y funcionando',
    documentacion_swagger: '/api-docs'
  });
});

// Especificación OpenAPI 3.0 para Swagger UI
const openApiSpec = {
  openapi: '3.0.0',
  info: {
    title: 'API de Login y Usuarios - Parqueo',
    version: '1.0.0',
    description: 'Documentación interactiva para Registro, Login y Gestión de Roles (1 = Admin, 2 = Usuario).'
  },
  servers: [
    {
      url: 'https://apilogin-qh0o.onrender.com',
      description: 'Servidor en Render (Producción)'
    },
    {
      url: 'http://localhost:3000',
      description: 'Servidor Local (localhost:3000)'
    }
  ],
  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'x-api-key',
        description: 'Ingresa tu API Key (ej. LoginParqueo_2026_JVC_KEY)'
      }
    }
  },
  security: [{ ApiKeyAuth: [] }],
  paths: {
    '/api/registro': {
      post: {
        summary: 'Registrar un nuevo usuario (asigna rol = 2 automáticamente)',
        tags: ['Autenticación'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['nombre', 'apellido', 'usuario', 'correo', 'password'],
                properties: {
                  nombre: { type: 'string', example: 'Admin' },
                  apellido: { type: 'string', example: 'Principal' },
                  usuario: { type: 'string', example: 'adminparqueo' },
                  correo: { type: 'string', example: 'admin@parqueo.com' },
                  password: { type: 'string', example: 'Admin123456' }
                }
              }
            }
          }
        },
        responses: {
          201: { description: 'Usuario registrado exitosamente' },
          400: { description: 'Faltan campos obligatorios' },
          401: { description: 'API Key inválida o no proporcionada' },
          409: { description: 'El usuario o correo ya existe' }
        }
      }
    },
    '/api/login': {
      post: {
        summary: 'Iniciar sesión y obtener datos del usuario (incluyendo su ID y rol)',
        tags: ['Autenticación'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['correo', 'password'],
                properties: {
                  correo: { type: 'string', example: 'admin@parqueo.com' },
                  password: { type: 'string', example: 'Admin123456' }
                }
              }
            }
          }
        },
        responses: {
          200: { description: 'Inicio de sesión exitoso' },
          401: { description: 'Credenciales inválidas o API Key incorrecta' }
        }
      }
    },
    '/api/usuarios/{id}': {
      get: {
        summary: 'Consultar datos de un usuario por su ID',
        tags: ['Usuarios'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'ID del usuario en Supabase'
          }
        ],
        responses: {
          200: { description: 'Datos del usuario' },
          404: { description: 'Usuario no encontrado' }
        }
      }
    },
    '/api/usuarios/{id}/rol': {
      put: {
        summary: 'Cambiar el rol de un usuario (1 = Admin, 2 = Usuario)',
        tags: ['Usuarios'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'ID del usuario que deseas convertir en Admin'
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['rol'],
                properties: {
                  rol: {
                    type: 'integer',
                    enum: [1, 2],
                    example: 1,
                    description: '1 = Administrador, 2 = Usuario normal'
                  }
                }
              }
            }
          }
        },
        responses: {
          200: { description: 'Rol actualizado exitosamente' },
          404: { description: 'Usuario no encontrado' }
        }
      }
    },
    '/api/usuarios/{id}/password': {
      put: {
        summary: 'Cambiar la contraseña de un usuario',
        tags: ['Usuarios'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'ID del usuario'
          }
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['passwordActual', 'passwordNuevo'],
                properties: {
                  passwordActual: { type: 'string', example: 'Admin123456' },
                  passwordNuevo: { type: 'string', example: 'NuevaClave2026' }
                }
              }
            }
          }
        },
        responses: {
          200: { description: 'Contraseña actualizada correctamente' },
          401: { description: 'La contraseña actual es incorrecta' }
        }
      }
    }
  }
};

app.get('/openapi.json', (req, res) => {
  res.json(openApiSpec);
});

app.get('/api-docs', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Swagger UI - API Login Parqueo</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        persistAuthorization: true
      });
    };
  </script>
</body>
</html>`);
});

const validarApiKey = (req, res, next) => {
  const apiKey = req.header('x-api-key');

  if (!apiKey || apiKey !== MI_API_KEY_SECRETA) {
    return res.status(401).json({
      ok: false,
      mensaje: 'No autorizado: API Key inválida o no proporcionada'
    });
  }

  next();
};

app.post('/api/registro', validarApiKey, async (req, res) => {
  try {
    const { nombre, apellido, usuario, correo, password, contrasena } = req.body;
    const passwordPlano = password || contrasena;

    if (!nombre || !apellido || !usuario || !correo || !passwordPlano) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Todos los campos obligatorios son requeridos (nombre, apellido, usuario, correo, password)'
      });
    }

    const saltRounds = 10;
    const passwordEncriptado = await bcrypt.hash(passwordPlano, saltRounds);

    // Por seguridad, el registro público siempre fuerza rol = 2 (Usuario normal)
    const nuevoUsuario = {
      nombre,
      apellido,
      usuario,
      correo,
      password: passwordEncriptado,
      rol: 2
    };

    const { data, error } = await supabase
      .from('usuarios')
      .insert([nuevoUsuario])
      .select('id, created_at, nombre, apellido, usuario, correo, rol')
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({
          ok: false,
          mensaje: 'El usuario o el correo electrónico ya se encuentran registrados',
          detalle: error.message
        });
      }

      return res.status(500).json({
        ok: false,
        mensaje: 'Error al registrar el usuario en la base de datos',
        detalle: error.message
      });
    }

    return res.status(201).json({
      ok: true,
      mensaje: 'Usuario registrado exitosamente',
      usuario: data
    });
  } catch (err) {
    console.error('Error en POST /api/registro:', err);
    return res.status(500).json({
      ok: false,
      mensaje: 'Error interno del servidor al procesar el registro'
    });
  }
});

app.post('/api/login', validarApiKey, async (req, res) => {
  try {
    const { correo, password, contrasena } = req.body;
    const passwordPlano = password || contrasena;

    if (!correo || !passwordPlano) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Debes proporcionar el correo y el password'
      });
    }

    const { data: usuarioEncontrado, error } = await supabase
      .from('usuarios')
      .select('id, nombre, apellido, usuario, correo, password, rol')
      .eq('correo', correo)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        mensaje: 'Error al consultar la base de datos',
        detalle: error.message
      });
    }

    if (!usuarioEncontrado) {
      return res.status(401).json({
        ok: false,
        mensaje: 'Credenciales inválidas'
      });
    }

    const passwordValido = await bcrypt.compare(passwordPlano, usuarioEncontrado.password);

    if (!passwordValido) {
      return res.status(401).json({
        ok: false,
        mensaje: 'Credenciales inválidas'
      });
    }

    return res.status(200).json({
      ok: true,
      mensaje: 'Inicio de sesión exitoso',
      usuario: {
        id: usuarioEncontrado.id,
        nombre: usuarioEncontrado.nombre,
        apellido: usuarioEncontrado.apellido,
        usuario: usuarioEncontrado.usuario,
        correo: usuarioEncontrado.correo,
        rol: usuarioEncontrado.rol
      }
    });
  } catch (err) {
    console.error('Error en POST /api/login:', err);
    return res.status(500).json({
      ok: false,
      mensaje: 'Error interno del servidor al procesar el inicio de sesión'
    });
  }
});

app.get('/api/usuarios/:id', validarApiKey, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('usuarios')
      .select('id, created_at, nombre, apellido, usuario, correo, rol')
      .eq('id', id)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        mensaje: 'Error al consultar el usuario',
        detalle: error.message
      });
    }

    if (!data) {
      return res.status(404).json({
        ok: false,
        mensaje: 'Usuario no encontrado'
      });
    }

    return res.status(200).json({
      ok: true,
      usuario: data
    });
  } catch (err) {
    console.error('Error en GET /api/usuarios/:id:', err);
    return res.status(500).json({
      ok: false,
      mensaje: 'Error interno del servidor'
    });
  }
});

app.put('/api/usuarios/:id/password', validarApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const { passwordActual, passwordNuevo } = req.body;

    if (!passwordActual || !passwordNuevo) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Debes enviar passwordActual y passwordNuevo'
      });
    }

    const { data: usuarioEncontrado, error: errorBusqueda } = await supabase
      .from('usuarios')
      .select('id, password')
      .eq('id', id)
      .maybeSingle();

    if (errorBusqueda || !usuarioEncontrado) {
      return res.status(404).json({
        ok: false,
        mensaje: 'Usuario no encontrado'
      });
    }

    const coincide = await bcrypt.compare(passwordActual, usuarioEncontrado.password);
    if (!coincide) {
      return res.status(401).json({
        ok: false,
        mensaje: 'La contraseña actual es incorrecta'
      });
    }

    const nuevoHash = await bcrypt.hash(passwordNuevo, 10);
    const { error: errorUpdate } = await supabase
      .from('usuarios')
      .update({ password: nuevoHash })
      .eq('id', id);

    if (errorUpdate) {
      return res.status(500).json({
        ok: false,
        mensaje: 'No se pudo actualizar la contraseña',
        detalle: errorUpdate.message
      });
    }

    return res.status(200).json({
      ok: true,
      mensaje: 'Contraseña actualizada correctamente'
    });
  } catch (err) {
    console.error('Error en PUT /api/usuarios/:id/password:', err);
    return res.status(500).json({
      ok: false,
      mensaje: 'Error interno del servidor al cambiar la contraseña'
    });
  }
});

app.put('/api/usuarios/:id/rol', validarApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const { rol } = req.body;

    if (rol === undefined || rol === null) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Debes especificar el nuevo rol (1 = Admin, 2 = Usuario)'
      });
    }

    const { data, error } = await supabase
      .from('usuarios')
      .update({ rol })
      .eq('id', id)
      .select('id, nombre, apellido, usuario, correo, rol')
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        mensaje: 'Error al actualizar el rol del usuario',
        detalle: error.message
      });
    }

    if (!data) {
      return res.status(404).json({
        ok: false,
        mensaje: 'Usuario no encontrado'
      });
    }

    return res.status(200).json({
      ok: true,
      mensaje: 'Rol actualizado exitosamente',
      usuario: data
    });
  } catch (err) {
    console.error('Error en PUT /api/usuarios/:id/rol:', err);
    return res.status(500).json({
      ok: false,
      mensaje: 'Error interno del servidor al actualizar el rol'
    });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});

