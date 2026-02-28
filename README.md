# HabboTracker 🍄 by Fungi

Explorador de la API de Habbo.es con red social (funas, posts, recomendaciones).

## Estructura del repositorio

```
habbotracker/
├── frontend/
│   └── index.html          ← Frontend (Netlify)
├── backend/
│   ├── server.js           ← API Node.js (Render.com)
│   ├── package.json
│   └── .gitignore
├── netlify.toml            ← Config Netlify
└── .gitignore
```

## Deploy: paso a paso

### 1. Sube el código a GitHub
Crea un repositorio en github.com con este contenido.

### 2. Backend en Render.com (gratis)

1. Entra a https://render.com → **New Web Service**
2. Conecta tu repo de GitHub
3. Configura:
   - **Root directory:** `backend`
   - **Runtime:** Node
   - **Build command:** *(vacío)*
   - **Start command:** `node server.js`
4. En **Environment Variables** agrega:
   - `FRONTEND_ORIGIN` = `https://TU-APP.netlify.app` (lo sabrás después de desplegar el frontend)
5. Haz click en **Create Web Service**
6. Copia la URL que te da Render (ej: `https://habbotracker-api.onrender.com`)

### 3. Frontend en Netlify

1. En `frontend/index.html`, línea ~5 del script:
   ```js
   return 'https://TU-APP.onrender.com';  // ← pon tu URL de Render
   ```
2. Entra a https://app.netlify.com → **Add new site → Import from Git**
3. Conecta tu repo de GitHub
4. Netlify detecta automáticamente el `netlify.toml`
5. Haz click en **Deploy site**

### 4. Actualizar CORS en Render

Una vez tengas la URL de Netlify, ve a Render → tu servicio → Environment:
- Actualiza `FRONTEND_ORIGIN` = `https://tuapp.netlify.app`
- Haz redeploy

## Variables de entorno del backend

| Variable          | Descripción                        | Ejemplo                              |
|-------------------|------------------------------------|--------------------------------------|
| `PORT`            | Puerto (Render lo pone automático) | `3001`                               |
| `FRONTEND_ORIGIN` | URL exacta del frontend            | `https://habbotracker.netlify.app`   |

## Notas

- Los datos (usuarios, posts, imágenes) se guardan en `backend/data/` que es local al servidor.  
  Render free tier puede reiniciarse y borrar datos. Para producción real considera usar una base de datos externa.
- Las imágenes subidas también se almacenan localmente en `backend/data/uploads/`.
- Contraseñas hasheadas con PBKDF2-SHA512 + salt aleatorio.
