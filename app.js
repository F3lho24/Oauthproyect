const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares de seguridad
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests por ventana de tiempo
    message: { error: 'Demasiadas solicitudes, intenta más tarde' }
});
app.use(limiter);

// Rate limiting específico para auth
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // máximo 5 intentos de login por 15 minutos
    message: { error: 'Demasiados intentos de login, intenta más tarde' }
});

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/radicalstore', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Esquema de Usuario
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Email inválido']
    },
    username: {
        type: String,
        required: function() { return !this.googleId && !this.facebookId; },
        unique: true,
        sparse: true
    },
    password: {
        type: String,
        required: function() { return !this.googleId && !this.facebookId; },
        minlength: 6
    },
    googleId: String,
    facebookId: String,
    name: String,
    avatar: String,
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date
}, {
    timestamps: true
});

// Virtual para verificar si la cuenta está bloqueada
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Métodos del usuario
userSchema.methods.incLoginAttempts = function() {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $unset: { lockUntil: 1, loginAttempts: 1 }
        });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
        updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 horas
    }

    return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
    return this.updateOne({
        $unset: { loginAttempts: 1, lockUntil: 1 }
    });
};

// Hash password antes de guardar
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Configuración de Passport
app.use(passport.initialize());

// Estrategia de Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('Google Profile:', profile);

        let user = await User.findOne({ googleId: profile.id });

        if (user) {
            user.lastLogin = new Date();
            // Actualizar información si ha cambiado
            if (profile.photos && profile.photos[0]) {
                user.avatar = profile.photos[0].value;
            }
            user.name = profile.displayName;
            await user.save();
            return done(null, user);
        }

        // Verificar si existe usuario con el mismo email
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        if (email) {
            user = await User.findOne({ email: email.toLowerCase() });
            if (user) {
                // Vincular cuenta existente con Google
                user.googleId = profile.id;
                user.name = profile.displayName;
                if (profile.photos && profile.photos[0]) {
                    user.avatar = profile.photos[0].value;
                }
                user.isVerified = true;
                user.lastLogin = new Date();
                await user.save();
                return done(null, user);
            }
        }

        // Crear nuevo usuario
        user = new User({
            googleId: profile.id,
            email: email ? email.toLowerCase() : null,
            name: profile.displayName,
            avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
            isVerified: true,
            lastLogin: new Date()
        });

        await user.save();
        console.log('Nuevo usuario creado con Google:', user.email);
        done(null, user);
    } catch (error) {
        console.error('Error en autenticación Google:', error);
        done(error, null);
    }
}));

// Estrategia de Facebook
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "/auth/facebook/callback",
    profileFields: ['id', 'emails', 'name', 'picture.type(large)']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ facebookId: profile.id });

        if (user) {
            user.lastLogin = new Date();
            await user.save();
            return done(null, user);
        }

        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;

        if (email) {
            user = await User.findOne({ email });
            if (user) {
                user.facebookId = profile.id;
                user.lastLogin = new Date();
                await user.save();
                return done(null, user);
            }
        }

        user = new User({
            facebookId: profile.id,
            email: email,
            name: `${profile.name.givenName} ${profile.name.familyName}`,
            avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
            isVerified: true,
            lastLogin: new Date()
        });

        await user.save();
        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

// Middleware de autenticación JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'tu_jwt_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
};

// Función para verificar reCAPTCHA
const verifyRecaptcha = async (recaptchaToken, version = 'v3') => {
    try {
        const secretKey = version === 'v3'
            ? process.env.RECAPTCHA_V3_SECRET_KEY
            : process.env.RECAPTCHA_V2_SECRET_KEY;

        if (!secretKey) {
            console.warn('reCAPTCHA secret key no configurada');
            return { success: true, score: 1.0 }; // Permitir en desarrollo
        }

        const response = await axios.post(
            'https://www.google.com/recaptcha/api/siteverify',
            new URLSearchParams({
                secret: secretKey,
                response: recaptchaToken,
                remoteip: process.env.NODE_ENV === 'development' ? '127.0.0.1' : undefined
            }),
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 5000
            }
        );

        const result = response.data;

        if (version === 'v3') {
            const threshold = parseFloat(process.env.RECAPTCHA_V3_THRESHOLD) || 0.5;
            const score = result.score || 0;

            console.log(`reCAPTCHA v3 - Score: ${score}, Threshold: ${threshold}`);

            return {
                success: result.success && score >= threshold,
                score: score,
                action: result.action,
                hostname: result.hostname
            };
        }

        // Para reCAPTCHA v2
        return {
            success: result.success,
            hostname: result.hostname,
            challenge_ts: result.challenge_ts
        };

    } catch (error) {
        console.error('Error verificando reCAPTCHA:', error.message);

        // En desarrollo, permitir si hay error de red
        if (process.env.NODE_ENV === 'development') {
            console.warn('reCAPTCHA fallback - permitiendo en desarrollo');
            return { success: true, score: 1.0 };
        }

        return { success: false, error: 'Error de verificación' };
    }
};

// Middleware para verificar reCAPTCHA
const requireRecaptcha = (version = 'v3') => {
    return async (req, res, next) => {
        const recaptchaToken = req.body.recaptchaToken || req.headers['x-recaptcha-token'];

        if (!recaptchaToken) {
            return res.status(400).json({
                error: 'Token reCAPTCHA requerido',
                code: 'RECAPTCHA_MISSING'
            });
        }

        try {
            const verification = await verifyRecaptcha(recaptchaToken, version);

            if (!verification.success) {
                console.warn('reCAPTCHA fallido:', verification);
                return res.status(403).json({
                    error: 'Verificación reCAPTCHA fallida',
                    code: 'RECAPTCHA_FAILED',
                    details: process.env.NODE_ENV === 'development' ? verification : undefined
                });
            }

            // Añadir información de reCAPTCHA al request
            req.recaptcha = verification;
            next();

        } catch (error) {
            console.error('Error en middleware reCAPTCHA:', error);
            return res.status(500).json({
                error: 'Error interno de verificación',
                code: 'RECAPTCHA_ERROR'
            });
        }
    };
};

// Función para generar JWT
const generateToken = (user) => {
return jwt.sign(
    {
        id: user._id,
        email: user.email,
        username: user.username
    },
    process.env.JWT_SECRET || 'tu_jwt_secret_key',
    { expiresIn: '24h' }
    );
};

// Registro tradicional
app.post('/api/auth/register', requireRecaptcha('v3'), async (req, res) => {
        try {
            const { email, username, password } = req.body;

            // Validaciones
            if (!email || !username || !password) {
                return res.status(400).json({
                    error: 'Email, usuario y contraseña son requeridos'
                });
            }

            if (!validator.isEmail(email)) {
                return res.status(400).json({ error: 'Email inválido' });
            }

            if (password.length < 6) {
                return res.status(400).json({
                    error: 'La contraseña debe tener al menos 6 caracteres'
                });
            }

            // Verificar si el usuario ya existe
            const existingUser = await User.findOne({
                $or: [{ email: email.toLowerCase() }, { username }]
            });

            if (existingUser) {
                return res.status(400).json({
                    error: 'El email o usuario ya están registrados'
                });
            }

            // Crear nuevo usuario
            const user = new User({
                email: email.toLowerCase(),
                username,
                password
            });

            await user.save();

            // Generar token
            const token = generateToken(user);

            res.status(201).json({
                message: 'Usuario registrado exitosamente',
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    name: user.name,
                    avatar: user.avatar
                }
            });

        } catch (error) {
            console.error('Error en registro:', error);
            res.status(500).json({ error: 'Error interno del servidor' });
        }
    });

// Login tradicional
    app.post('/api/auth/login', authLimiter, requireRecaptcha('v3'), async (req, res) => {
        try {
            const { username, password } = req.body;

            if (!username || !password) {
                return res.status(400).json({
                    error: 'Usuario y contraseña son requeridos'
                });
            }

            // Buscar usuario por username o email
            const user = await User.findOne({
                $or: [
                    { username },
                    { email: username.toLowerCase() }
                ]
            });

            if (!user) {
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }

            // Verificar si la cuenta está bloqueada
            if (user.isLocked) {
                return res.status(423).json({
                    error: 'Cuenta temporalmente bloqueada por múltiples intentos fallidos'
                });
            }

            // Verificar contraseña
            const isValidPassword = await user.comparePassword(password);

            if (!isValidPassword) {
                await user.incLoginAttempts();
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }

            // Reset intentos de login y actualizar último login
            await user.resetLoginAttempts();
            user.lastLogin = new Date();
            await user.save();

            // Generar token
            const token = generateToken(user);

            res.json({
                message: 'Login exitoso',
                token,
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    name: user.name,
                    avatar: user.avatar
                }
            });

        } catch (error) {
            console.error('Error en login:', error);
            res.status(500).json({ error: 'Error interno del servidor' });
        }
    });

// Ruta para verificar email (registro por email)
    app.post('/api/auth/register-email', requireRecaptcha('v3'), async (req, res) => {
        try {
            const { email } = req.body;

            if (!email || !validator.isEmail(email)) {
                return res.status(400).json({ error: 'Email válido requerido' });
            }

            // Verificar si el email ya existe
            const existingUser = await User.findOne({ email: email.toLowerCase() });

            if (existingUser) {
                return res.status(400).json({
                    error: 'Este email ya está registrado'
                });
            }

            // En un escenario real, aquí enviarías un email de verificación
            // Por ahora, simplemente confirmamos que el email está disponible
            res.json({
                message: 'Email disponible',
                email: email.toLowerCase(),
                nextStep: 'complete_registration'
            });

        } catch (error) {
            console.error('Error verificando email:', error);
            res.status(500).json({ error: 'Error interno del servidor' });
        }
    });

// Rutas de autenticación social
    app.get('/auth/google',
        passport.authenticate('google', { scope: ['profile', 'email'] })
    );

    app.get('/auth/google/callback',
        passport.authenticate('google', { session: false, failureRedirect: '/auth/failure' }),
        (req, res) => {
            try {
                const token = generateToken(req.user);
                // Redirigir al frontend con el token
                res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}?token=${token}&success=true`);
            } catch (error) {
                console.error('Error generando token:', error);
                res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}?error=auth_failed`);
            }
        }
    );

// Ruta de fallo de autenticación
    app.get('/auth/failure', (req, res) => {
        res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}?error=auth_failed`);
    });

// Endpoint para iniciar autenticación Google desde AJAX
    app.get('/api/auth/google/url', (req, res) => {
        const authUrl = `${req.protocol}://${req.get('host')}/auth/google`;
        res.json({ authUrl });
    });

    app.get('/auth/facebook',
        passport.authenticate('facebook', { scope: ['email'] })
    );

    app.get('/auth/facebook/callback',
        passport.authenticate('facebook', { session: false }),
        (req, res) => {
            const token = generateToken(req.user);
            res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}?token=${token}`);
        }
    );

// Ruta para obtener perfil del usuario
    app.get('/api/auth/profile', authenticateToken, async (req, res) => {
        try {
            const user = await User.findById(req.user.id).select('-password');
            if (!user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            res.json({
                user: {
                    id: user._id,
                    email: user.email,
                    username: user.username,
                    name: user.name,
                    avatar: user.avatar,
                    isVerified: user.isVerified,
                    lastLogin: user.lastLogin
                }
            });
        } catch (error) {
            console.error('Error obteniendo perfil:', error);
            res.status(500).json({ error: 'Error interno del servidor' });
        }
    });

// Ruta para logout (invalidar token - en un escenario real usarías una blacklist)
    app.post('/api/auth/logout', authenticateToken, (req, res) => {
        res.json({ message: 'Logout exitos' });
    });

// Ruta de salud
    app.get('/health', (req, res) => {
        res.json({ status: 'OK', timestamp: new Date().toISOString() });
    });

// Manejo de errores global
    app.use((error, req, res) => {
        console.error('Error global:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    });

// Iniciar servidor
    app.listen(PORT, () => {
        console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
        console.log(`📱 Health check: http://localhost:${PORT}/health`);
    });

    module.exports = app;