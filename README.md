# API de autenticación

API de servidor a servidor para registrar usuarios e iniciar sesión. El navegador no debe llamar a esta API directamente ni recibir `API_SERVICE_KEY`, `SUPABASE_KEY` o `JWT_SECRET`. CORS solo limita el acceso desde navegadores: no autentica clientes. Las rutas de integración se autentican mediante `x-api-key`, que debe enviarse exclusivamente desde la API de parqueos.

## Variables de entorno

Configura estas variables en el gestor de secretos del servidor; no guardes valores reales en el repositorio:

| Variable | Requerida | Descripción |
| --- | --- | --- |
| `SUPABASE_URL` | Sí | URL del proyecto Supabase. |
| `SUPABASE_KEY` | Sí | Clave de servidor Supabase con permisos necesarios para la tabla `usuarios`; nunca usarla desde el navegador. |
| `API_SERVICE_KEY` | Sí | Credencial aleatoria de al menos 32 bytes. Configura el mismo valor en el servidor de parqueos y en esta API; el cliente web no debe conocerla. |
| `ADMIN_SERVICE_KEY` | Sí | Credencial independiente de al menos 32 bytes, solo para el proceso interno autorizado a asignar roles administrativos. No compartirla con el servidor de parqueos salvo que ese sea explícitamente el proceso privilegiado. |
| `JWT_SECRET` | Sí | Secreto aleatorio de al menos 32 bytes. Configura exactamente el mismo valor en ambas APIs para que parqueos pueda verificar los JWT. No es el `API_SERVICE_KEY`. |
| `JWT_EXPIRES_IN` | No | Caducidad aceptada por `jsonwebtoken`; por defecto `8h`. |
| `CORS_ORIGINS` | No | Orígenes web explícitamente permitidos, separados por comas. Por defecto no se permite ningún origen de navegador. Las llamadas servidor a servidor no dependen de CORS. |
| `PORT` | No | Puerto HTTP; por defecto `3000`. |

Genera secretos nuevos con un generador criptográficamente seguro (por ejemplo, `openssl rand -base64 48`) y distribúyelos mediante los gestores de secretos de ambos servidores. Rota inmediatamente cualquier valor que haya sido publicado en el frontend, en documentación, en Git o en registros. La rotación de credenciales de despliegues externos debe realizarse en sus respectivos gestores de secretos; este repositorio no contiene credenciales reales.

`npm start` valida al arrancar que existan `SUPABASE_URL`, `SUPABASE_KEY`, `API_SERVICE_KEY`, `ADMIN_SERVICE_KEY` y `JWT_SECRET`, y que los tres secretos tengan al menos 32 bytes. No registra sus valores.

## Contrato de autenticación

Las rutas de registro y login requieren `Content-Type: application/json` y `x-api-key: <API_SERVICE_KEY>`. No aceptan un JWT de usuario como sustituto de la credencial de servicio.

### `POST /api/registro`

Campos requeridos: `nombre` (1–80 caracteres), `apellido` (1–80), `usuario` (1–50), `correo` (email de hasta 254 caracteres) y `password` (8–72 bytes UTF-8). Se conserva `contrasena` como alias de `password`. El correo se recorta y se convierte a minúsculas antes de guardar. La API asigna siempre el rol público `2`; cualquier `rol` del cuerpo se ignora. La asignación de rol administrador (`1`) queda reservada a `PUT /api/usuarios/:id/rol`, protegida por la credencial independiente `ADMIN_SERVICE_KEY`; no acepta `API_SERVICE_KEY`.

Éxito: HTTP `201`.

```json
{
  "ok": true,
  "mensaje": "Usuario registrado exitosamente",
  "token": "<JWT>",
  "access_token": "<JWT>",
  "usuario": {
    "id": "id-generado-por-supabase",
    "nombre": "Juan",
    "apellido": "Pérez",
    "usuario": "jperez",
    "correo": "juan@correo.com",
    "rol": 2
  }
}
```

### `POST /api/login`

Campos requeridos: `correo` y `password` (se acepta también `contrasena`). El correo se normaliza de la misma manera que en registro. La respuesta exitosa HTTP `200` tiene la misma forma de `usuario` y contiene el JWT en `token`. `access_token` se conserva como alias por compatibilidad. Ninguna respuesta incluye el hash ni la contraseña.

`usuario.id` es el identificador persistente generado por la base de datos. Parqueos debe guardarlo como ID externo y no derivarlo del correo. La tabla `usuarios` debe tener `id` como clave primaria única con generación de valor en la base de datos; la API nunca lo modifica. `correo` debe tener una restricción/índice único insensible a mayúsculas (por ejemplo, un índice único sobre `lower(correo)`), y los registros históricos duplicados deben resolverse antes de crearlo.

### Autenticación de otras rutas

- `GET /api/verificar-token` y `GET /api/perfil` aceptan `Authorization: Bearer <JWT>` y verifican firma HMAC-SHA-256 y expiración usando `JWT_SECRET`.
- Las rutas `/api/usuarios/:id` y `/api/usuarios/:id/password` requieren `API_SERVICE_KEY`. `PUT /api/usuarios/:id/rol` requiere `ADMIN_SERVICE_KEY` y queda reservado al proceso interno autorizado; no debe exponerse como proxy abierto a usuarios.

Respuestas de error: `400` entrada inválida/JSON mal formado, `401` credencial de servicio o credenciales de usuario inválidas, `409` usuario/correo duplicado, `404` usuario inexistente, `413` cuerpo demasiado grande, `503` error de base de datos y `500` error interno. Los errores no incluyen detalles internos de Supabase ni datos sensibles.

## Configuración de Supabase

La tabla `usuarios` debe contar con columnas `id`, `nombre`, `apellido`, `usuario`, `correo`, `password` y `rol`. `id` debe tener un valor predeterminado generado por la base de datos (UUID o identidad) y ser único; no debe basarse en el correo. Configura una restricción única para evitar correos duplicados independientemente de mayúsculas/minúsculas.

## Pruebas

Ejecuta `npm test` para las pruebas de contrato, rol público, correo duplicado, login válido e inválido y firma JWT. Las pruebas usan una base Supabase simulada y no requieren secretos de producción.
