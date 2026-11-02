# Documentación de la API de Login y Usuarios

Hola, aquí tienes los datos para conectar el sistema de Login, Registro y Gestión de Usuarios:

**URL Base:** https://apilogin-qh0o.onrender.com

---

## 1. Seguridad (Obligatorio para todas las peticiones)

En los **Headers** de cada petición debes enviar:

```http
Content-Type: application/json
x-api-key: LoginParqueo_2026_JVC_KEY
```

---

## 2. Ruta de Registro

- **Método y Ruta:** `POST /api/registro`
- **URL completa:** `https://apilogin-qh0o.onrender.com/api/registro`
- **Body (JSON):** `nombre`, `apellido`, `usuario`, `correo`, `password` *(también acepta `contrasena`)*. El backend asigna y fuerza automáticamente `rol = 2` (Usuario normal).

```json
{
  "nombre": "Juan",
  "apellido": "Pérez",
  "usuario": "jperez",
  "correo": "juan@correo.com",
  "password": "MiPassword123"
}
```

---

## 3. Ruta de Login

- **Método y Ruta:** `POST /api/login`
- **URL completa:** `https://apilogin-qh0o.onrender.com/api/login`
- **Body (JSON):** `correo` y `password` *(también acepta `contrasena`)*.

```json
{
  "correo": "juan@correo.com",
  "password": "MiPassword123"
}
```

*(Si es correcto, devolverá un status `200` con `ok: true` y los datos del usuario: `id`, `nombre`, `apellido`, `usuario`, `correo` y `rol`).*

---

## 4. Consultar datos de un usuario por ID

- **Método y Ruta:** `GET /api/usuarios/:id`
- **URL completa:** `https://apilogin-qh0o.onrender.com/api/usuarios/AQUI_EL_ID_DEL_USUARIO`

*(Devuelve la información del usuario sin mostrar la contraseña).*

---

## 5. Cambiar contraseña de un usuario

- **Método y Ruta:** `PUT /api/usuarios/:id/password`
- **URL completa:** `https://apilogin-qh0o.onrender.com/api/usuarios/AQUI_EL_ID_DEL_USUARIO/password`
- **Body (JSON):** `passwordActual` y `passwordNuevo`.

```json
{
  "passwordActual": "MiPassword123",
  "passwordNuevo": "NuevaClave456"
}
```

---

## 6. Modificar el rol de un usuario (Ascender o cambiar permisos)

- **Método y Ruta:** `PUT /api/usuarios/:id/rol`
- **URL completa:** `https://apilogin-qh0o.onrender.com/api/usuarios/AQUI_EL_ID_DEL_USUARIO/rol`
- **Body (JSON):** `rol` (`1` = Admin, `2` = Usuario).

```json
{
  "rol": 1
}
```

