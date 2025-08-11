# 🚀 Guía Completa de Implementación - Sistema de Autenticación con reCAPTCHA

## 📋 Requisitos Previos

- **Node.js** (versión 16 o superior)
- **MongoDB** (local o MongoDB Atlas)
- **Navegador web moderno**
- **Editor de código** (VS Code recomendado)
- **Cuenta de Google** (para reCAPTCHA y OAuth)

## 🛠️ Configuración Paso a Paso

### 1. Configuración del Backend

```bash
# 1. Crear directorio del proyecto
mkdir radicalstore-auth
cd radicalstore-auth

# 2. Inicializar npm
npm init -y

# 3. Instalar dependencias
npm install express mongoose bcryptjs jsonwebtoken cors passport passport-google-oauth20 passport-facebook express-rate-limit helmet validator dotenv nodemailer axios

# 4. Instalar dependencias de desarrollo
npm install --save-dev nodemon jest supertest eslint
```

### 2. Estructura de Archivos

```
radicalstore-auth/
├── server.js              # Servidor principal
├── package.json           # Dependencias
├── .env                   # Variables de entorno (crear)
├── .env.example          # Ejemplo de variables
├── start.js              # Script de configuración
├── test-recaptcha.js     # Script de testing reCAPTCHA
├── public/               # Archivos estáticos
│   └── index.html        # Frontend
└── README.md             # Documentación
```

### 3. Configuración de Google reCAPTCHA

#### Paso A: Crear sitios reCAPTCHA
1. Ve a [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin/)
2. Crea **DOS sitios**:

**Sitio 1 - reCAPTCHA v3 (Recomendado):**
- Etiqueta: `RadicalStore Auth v3`
- Tipo: `reCAPTCHA v3`
- Dominios: `localhost`, `127.0.0.1`

**Sitio 2 - reCAPTCHA v2 (Fallback):**
- Etiqueta: `RadicalStore Auth v2`
- Tipo: `reCAPTCHA v2` → `Casilla "No soy un robot"`
- Dominios: `localhost`, `127.0.0.1`

#### Paso B: Obtener las claves
Cada sitio te dará:
- **Site Key** (pública): Para el frontend
- **Secret Key** (privada): Para el backend

### 4. Configuración de Google OAuth (del paso anterior)

Sigue los pasos de la configuración anterior de Google OAuth.

### 5. Configuración de Variables de Entorno

Crea archivo `.env`:

```env
# Servidor
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:3001

# Base de datos
MONGODB_URI=mongodb://localhost:27017/radicalstore

# JWT Secret (generar uno seguro)
JWT_SECRET=tu_jwt_secret_muy_seguro_aqui

# Google OAuth
GOOGLE_CLIENT_ID=123456789-abcdef.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu_client_secret_aqui

# reCAPTCHA v3 (Principal)
RECAPTCHA_V3_SITE_KEY=6LcXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
RECAPTCHA_V3_SECRET_KEY=6LcXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# reCAPTCHA v2 (Fallback)
RECAPTCHA_V2_SITE_KEY=6LcYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
RECAPTCHA_V2_SECRET_KEY=6LcYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

# Umbral reCAPTCHA v3 (0.0-1.0, recomendado: 0.5)
RECAPTCHA_V3_THRESHOLD=0.5
```

### 6. Configuración de MongoDB

#### Opción A: MongoDB Local
```bash
# Instalar MongoDB Community Edition
# Windows: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/
# macOS: brew install mongodb/brew/mongodb-community
# Ubuntu: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/

# Iniciar MongoDB
mongod --dbpath /tu/ruta/data/db
```

#### Opción B: MongoDB Atlas (Recomendado)
1. Ve a [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Crea cuenta gratuita
3. Crea cluster gratuito
4. Obtén connection string
5. Actualiza `MONGODB_URI` en `.env`

### 7. Ejecutar la Aplicación

```bash
# 1. Iniciar MongoDB (si es local)
mongod

# 2. En otra terminal, iniciar el backend
npm run dev
# o para producción: npm start

# 3. Verificar que funciona
# Abre: http://localhost:3000/health
# Deberías ver: {"status":"OK","timestamp":"..."}

# 4. Probar reCAPTCHA
node test-recaptcha.js
```

### 8. Configurar Frontend

1. Crea archivo `public/index.html` con el código del frontend
2. **Opción A:** Usar Live Server (VS Code)
   - Instala extensión "Live Server"
   - Click derecho en `index.html` > "Open with Live Server"
   - Se abrirá en `http://localhost:5500`

3. **Opción B:** Servidor estático simple
   ```bash
   # Instalar globally
   npm install -g http-server
   
   # Iniciar en directorio public/
   cd public
   http-server -p 3001
   ```

### 9. Testing de reCAPTCHA

#### Verificaciones Automáticas:
```bash
# Ejecutar script de testing
node test-recaptcha.js
```

#### Verificaciones Manuales:
1. **Backend funcionando:** http://localhost:3000/health
2. **Claves reCAPTCHA:** http://localhost:3000/api/auth/recaptcha-keys
3. **Frontend funcionando:** http://localhost:3001

#### Test de Funcionalidades:
1. **reCAPTCHA v3 (Invisible):**
   - Abre el frontend
   - Intenta registrarte/iniciar sesión
   - Debería funcionar sin intervención del usuario
   - Rev# 🚀 Guía Completa de Implementación - Sistema de Autenticación

## 📋 Requisitos Previos

- **Node.js** (versión 16 o superior)
- **MongoDB** (local o MongoDB Atlas)
- **Navegador web moderno**
- **Editor de código** (VS Code recomendado)

## 🛠️ Configuración Paso a Paso

### 1. Configuración del Backend

```bash
# 1. Crear directorio del proyecto
mkdir radicalstore-auth
cd radicalstore-auth

# 2. Inicializar npm
npm init -y

# 3. Instalar dependencias
npm install express mongoose bcryptjs jsonwebtoken cors passport passport-google-oauth20 passport-facebook express-rate-limit helmet validator dotenv nodemailer

# 4. Instalar dependencias de desarrollo
npm install --save-dev nodemon jest supertest eslint
```

### 2. Estructura de Archivos

```
radicalstore-auth/
├── server.js              # Servidor principal
├── package.json           # Dependencias
├── .env                   # Variables de entorno (crear)
├── .env.example          # Ejemplo de variables
├── start.js              # Script de configuración
├── public/               # Archivos estáticos
│   └── index.html        # Frontend
└── README.md             # Documentación
```

### 3. Configuración de Google OAuth

#### Paso A: Google Cloud Console
1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un nuevo proyecto: **"RadicalStore"**
3. Ve a **APIs y servicios > Credenciales**

#### Paso B: Configurar Pantalla de Consentimiento
1. Clic en **Configurar pantalla de consentimiento**
2. Selecciona **Externo**
3. Completa:
   - Nombre: **RadicalStore**
   - Email de soporte: tu email
   - Dominios autorizados: `localhost`
4. Guarda y continúa

#### Paso C: Crear Credenciales OAuth
1. Clic en **+ CREAR CREDENCIALES > ID de cliente de OAuth 2.0**
2. Tipo: **Aplicación web**
3. Nombre: **RadicalStore Web Client**
4. **Orígenes de JavaScript autorizados:**
   - `http://localhost:3000`
   - `http://localhost:3001`
5. **URIs de redirección autorizados:**
   - `http://localhost:3000/auth/google/callback`
6. Crear y copiar **Client ID** y **Client Secret**

### 4. Configuración de Variables de Entorno

Crea archivo `.env`:

```env
# Servidor
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:3001

# Base de datos
MONGODB_URI=mongodb://localhost:27017/radicalstore

# JWT Secret (generar uno seguro)
JWT_SECRET=tu_jwt_secret_muy_seguro_aqui

# Google OAuth (pegar tus credenciales)
GOOGLE_CLIENT_ID=123456789-abcdef.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu_client_secret_aqui

# Facebook OAuth (opcional por ahora)
FACEBOOK_APP_ID=tu_facebook_app_id
FACEBOOK_APP_SECRET=tu_facebook_app_secret
```

### 5. Configuración de MongoDB

#### Opción A: MongoDB Local
```bash
# Instalar MongoDB Community Edition
# Windows: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/
# macOS: brew install mongodb/brew/mongodb-community
# Ubuntu: https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/

# Iniciar MongoDB
mongod --dbpath /tu/ruta/data/db
```

#### Opción B: MongoDB Atlas (Recomendado)
1. Ve a [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Crea cuenta gratuita
3. Crea cluster gratuito
4. Obtén connection string
5. Actualiza `MONGODB_URI` en `.env`

### 6. Ejecutar la Aplicación

```bash
# 1. Iniciar MongoDB (si es local)
mongod

# 2. En otra terminal, iniciar el backend
npm run dev
# o para producción: npm start

# 3. Verificar que funciona
# Abre: http://localhost:3000/health
# Deberías ver: {"status":"OK","timestamp":"..."}
```

### 7. Configurar Frontend

1. Crea archivo `public/index.html` con el código del frontend
2. **Opción A:** Usar Live Server (VS Code)
   - Instala extensión "Live Server"
   - Click derecho en `index.html` > "Open with Live Server"
   - Se abrirá en `http://localhost:5500`

3. **Opción B:** Servidor estático simple
   ```bash
   # Instalar globally
   npm install -g http-server
   
   # Iniciar en directorio public/
   cd public
   http-server -p 3001
   ```

### 8. Testing de la Implementación

#### Verificaciones Básicas:
1. **Backend funcionando:** http://localhost:3000/health
2. **Frontend funcionando:** http://localhost:3001 (o tu puerto)
3. **Base de datos conectada:** No debería haber errores en consola

#### Test de Google OAuth:
1. Abre el frontend
2. Click en "Continuar con Google"
3. Debería abrir popup de Google
4. Después de autorizar, debería:
   - Cerrar popup
   - Mostrar dashboard
   - Guardar token en localStorage

#### Test de Registro/Login Tradicional:
1. Ir a "Regístrate aquí"
2. Ingresar email válido
3. Completar datos (usuario, contraseña)
4. Debería crear cuenta y mostrar dashboard

## 🔧 Solución de Problemas Comunes

### Error: "Google OAuth no funciona"
- ✅ Verifica que las URLs en Google Console coincidan exactamente
- ✅ Asegúrate de que CORS esté habilitado
- ✅ Revisa las credenciales en `.env`

### Error: "MongoDB connection failed"
- ✅ Verifica que MongoDB esté corriendo
- ✅ Revisa la URI de conexión
- ✅ Para Atlas: verifica IP whitelist y credenciales

### Error: "Cannot POST /api/auth/..."
- ✅ Verifica que el backend esté corriendo en puerto 3000
- ✅ Actualiza `API_BASE_URL` en el frontend si es necesario

### Error: "CORS policy"
- ✅ Verifica que `FRONTEND_URL` en `.env` coincida con tu URL del frontend
- ✅ Reinicia el servidor después de cambios en `.env`

## 🌐 URLs Importantes

- **Backend API:** http://localhost:3000
- **Frontend:** http://localhost:3001 (o tu puerto)
- **Health Check:** http://localhost:3000/health
- **Google Auth:** http://localhost:3000/auth/google
- **API Docs:** Endpoints disponibles en `/api/auth/...`

## 📱 Endpoints de la API

```
POST /api/auth/register        # Registro tradicional
POST /api/auth/login           # Login tradicional  
POST /api/auth/register-email  # Verificar email
GET  /api/auth/profile         # Obtener perfil
POST /api/auth/logout          # Cerrar sesión
GET  /auth/google              # Iniciar OAuth Google
GET  /auth/google/callback     # Callback OAuth Google
GET  /health                   # Estado del servidor
```

## 🚀 Próximos Pasos

1. **Personalización:** Cambia colores, logos, textos
2. **Validaciones:** Añade más validaciones de seguridad
3. **Emails:** Implementa verificación por email
4. **Facebook:** Configura OAuth de Facebook
5. **Recuperación:** Implementa reset de contraseña
6. **Testing:** Añade tests unitarios y de integración
7. **Deployment:** Prepara para producción (Heroku, Vercel, etc.)

## 🔒 Consideraciones de Seguridad

- ✅ Cambia `JWT_SECRET` en producción
- ✅ Usa HTTPS en producción
- ✅ Configura rate limiting apropiado
- ✅ Valida todas las entradas del usuario
- ✅ Mantén dependencias actualizadas
- ✅ Implementa logging de seguridad
