const { after, test } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { crearAplicacion, validarConfiguracion } = require('../index');

const SERVICE_KEY = 'test-service-key-0123456789-abcdefgh';
const ADMIN_KEY = 'test-admin-key-0123456789-abcdefgh';
const JWT_SECRET = 'test-jwt-secret-0123456789-abcdefghijkl';

class SupabaseFalso {
  constructor(users = []) {
    this.users = users;
    this.nextId = 1;
    this.errorOperacion = null;
  }

  from() {
    const query = {
      operation: 'select',
      filter: null,
      select: () => query,
      insert: (rows) => {
        query.operation = 'insert';
        query.row = rows[0];
        return query;
      },
      update: (values) => {
        query.operation = 'update';
        query.values = values;
        return query;
      },
      eq: (field, value) => {
        query.filter = { field, value };
        return query;
      },
      single: async () => {
        if (this.errorOperacion) return { data: null, error: this.errorOperacion };
        if (this.users.some((user) => (
          user.correo.toLowerCase() === query.row.correo.toLowerCase() ||
          user.usuario === query.row.usuario
        ))) {
          return { data: null, error: { code: '23505', message: 'duplicate' } };
        }
        const inserted = { id: `stable-id-${this.nextId++}`, ...query.row };
        this.users.push(inserted);
        return { data: inserted, error: null };
      },
      maybeSingle: async () => {
        if (this.errorOperacion) return { data: null, error: this.errorOperacion };
        const user = this.users.find((item) => item[query.filter.field] === query.filter.value);
        if (!user || query.operation !== 'update') return { data: user || null, error: null };
        Object.assign(user, query.values);
        return { data: user, error: null };
      }
    };
    return query;
  }
}

const iniciarServidor = async (supabase) => {
  const app = crearAplicacion({
    supabase,
    serviceKey: SERVICE_KEY,
    adminKey: ADMIN_KEY,
    jwtSecret: JWT_SECRET
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));
  return `http://127.0.0.1:${server.address().port}`;
};

const enviar = (baseUrl, path, body, { apiKey = SERVICE_KEY, method = 'POST', ...options } = {}) => fetch(`${baseUrl}${path}`, {
  method,
  headers: {
    'Content-Type': 'application/json',
    ...(apiKey ? { 'x-api-key': apiKey } : {}),
    ...options.headers
  },
  body: JSON.stringify(body)
});

test('validates that production secrets are configured and sufficiently long', () => {
  assert.throws(() => validarConfiguracion({}), /SUPABASE_URL/);
  assert.throws(() => validarConfiguracion({
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_KEY: 'supabase-key',
    API_SERVICE_KEY: SERVICE_KEY,
    ADMIN_SERVICE_KEY: ADMIN_KEY,
    JWT_SECRET: 'too-short'
  }), /JWT_SECRET/);
  assert.equal(validarConfiguracion({
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_KEY: 'supabase-key',
    API_SERVICE_KEY: SERVICE_KEY,
    ADMIN_SERVICE_KEY: ADMIN_KEY,
    JWT_SECRET
  }).jwtSecret, JWT_SECRET);
});

test('registers normalized email with server-assigned public role and parkings contract', async () => {
  const baseUrl = await iniciarServidor(new SupabaseFalso());
  const response = await enviar(baseUrl, '/api/registro', {
    nombre: 'Juan',
    apellido: 'Pérez',
    usuario: 'jperez',
    correo: ' Juan@Correo.com ',
    password: 'Password123',
    rol: 1
  });
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.ok, true);
  assert.deepEqual(
    { id: body.usuario.id, correo: body.usuario.correo, rol: body.usuario.rol },
    { id: 'stable-id-1', correo: 'juan@correo.com', rol: 2 }
  );
  assert.equal(body.token, body.access_token);
  const decoded = jwt.verify(body.token, JWT_SECRET, { algorithms: ['HS256'] });
  assert.equal(decoded.sub, body.usuario.id);
  assert.equal(decoded.correo, body.usuario.correo);
  assert.equal(decoded.rol, 2);
  assert.equal(Object.hasOwn(body.usuario, 'password'), false);
  assert.equal(JSON.stringify(body).includes('Password123'), false);
});

test('returns 409 for a duplicate email without exposing database details', async () => {
  const baseUrl = await iniciarServidor(new SupabaseFalso([{
    id: 'existing-id',
    nombre: 'Existing',
    apellido: 'User',
    usuario: 'existing',
    correo: 'duplicate@example.com',
    password: 'hash',
    rol: 2
  }]));
  const response = await enviar(baseUrl, '/api/registro', {
    nombre: 'New',
    apellido: 'User',
    usuario: 'newuser',
    correo: 'DUPLICATE@example.com',
    password: 'Password123'
  });
  const body = await response.json();

  assert.equal(response.status, 409);
  assert.equal(body.ok, false);
  assert.equal(JSON.stringify(body).includes('duplicate'), false);
});

test('logs in with normalized email and rejects invalid credentials', async () => {
  const passwordHash = await bcrypt.hash('Password123', 4);
  const baseUrl = await iniciarServidor(new SupabaseFalso([{
    id: 'stable-user-id',
    nombre: 'Juan',
    apellido: 'Pérez',
    usuario: 'jperez',
    correo: 'juan@example.com',
    password: passwordHash,
    rol: 2
  }]));

  const validResponse = await enviar(baseUrl, '/api/login', {
    correo: ' JUAN@EXAMPLE.COM ',
    password: 'Password123'
  });
  const validBody = await validResponse.json();
  assert.equal(validResponse.status, 200);
  assert.equal(validBody.ok, true);
  assert.deepEqual(
    { id: validBody.usuario.id, correo: validBody.usuario.correo, rol: validBody.usuario.rol },
    { id: 'stable-user-id', correo: 'juan@example.com', rol: 2 }
  );
  assert.equal(Object.hasOwn(validBody.usuario, 'password'), false);

  const invalidResponse = await enviar(baseUrl, '/api/login', {
    correo: 'juan@example.com',
    password: 'WrongPassword1'
  });
  assert.equal(invalidResponse.status, 401);
  assert.equal((await invalidResponse.json()).mensaje, 'Credenciales inválidas');
});

test('requires the private service credential and reports database errors safely', async () => {
  const supabase = new SupabaseFalso();
  const baseUrl = await iniciarServidor(supabase);
  const unauthorized = await enviar(baseUrl, '/api/login', {
    correo: 'juan@example.com',
    password: 'Password123'
  }, { apiKey: null });
  assert.equal(unauthorized.status, 401);

  supabase.errorOperacion = { code: 'DB_DOWN', message: 'sensitive internal details' };
  const failed = await enviar(baseUrl, '/api/login', {
    correo: 'juan@example.com',
    password: 'Password123'
  });
  const body = await failed.json();
  assert.equal(failed.status, 503);
  assert.equal(JSON.stringify(body).includes('sensitive'), false);
});

test('requires a separate administrator credential to assign a privileged role', async () => {
  const supabase = new SupabaseFalso([{
    id: 'stable-user-id',
    nombre: 'Juan',
    apellido: 'Pérez',
    usuario: 'jperez',
    correo: 'juan@example.com',
    password: 'hash',
    rol: 2
  }]);
  const baseUrl = await iniciarServidor(supabase);

  const denied = await enviar(baseUrl, '/api/usuarios/stable-user-id/rol', { rol: 1 }, {
    method: 'PUT'
  });
  assert.equal(denied.status, 401);

  const allowed = await enviar(baseUrl, '/api/usuarios/stable-user-id/rol', { rol: 1 }, {
    method: 'PUT',
    apiKey: ADMIN_KEY
  });
  assert.equal(allowed.status, 200);
  assert.equal((await allowed.json()).usuario.rol, 1);
});
