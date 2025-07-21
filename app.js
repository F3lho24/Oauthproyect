const express = require('express');
const cors = require('cors');
const app = express();
const axios = require('axios');
app.use(express.json());
app.use(cors()); // Permite peticiones desde el frontend


app.post('/api/auth/login', async (req, res) => {
    const { usuario, contrasena, recaptchaToken } = req.body;

    try {
        // Verificar reCAPTCHA
        const recaptchaRes = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify`,
            null,
            {
                params: {
                    secret: '6LePHYErAAAAAMsLMURQpH4iYBm0Patwj1EJ_iL6',
                    response: recaptchaToken
                }
            }
        );

        const { success, score } = recaptchaRes.data;
        if (!success || score < 0.5) {
            return res.status(401).json({ success: false, message: 'reCAPTCHA inválido' });
        }

        // Verificar usuario y contraseña
        const user = usuarios.find(u => u.usuario === usuario);
        if (!user || user.contrasena !== contrasena) {
            return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
        }

        res.json({ success: true, message: '¡Autenticación exitosa!', email: user.usuario });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ success: false, message: 'Error del servidor' });
    }
});

app.post('/api/auth/google', async (req, res) => {
    const { token, recaptchaToken } = req.body;

    try {
        // Verifica reCAPTCHA
        const response = await axios.post(
            `https://www.google.com/recaptcha/api/siteverify`,
            null,
            {
                params: {
                    secret: '6LePHYErAAAAAMsLMURQpH4iYBm0Patwj1EJ_iL6',
                    response: recaptchaToken,
                }
            }
        );

        const { success: recaptchaSuccess, score } = recaptchaResponse.data;
        if (!recaptchaSuccess || score < 0.5) {
            return res.status(401).json({ success: false, message: 'reCAPTCHA inválido.' });
        }

        // Verifica el token de Google OAuth
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: '6LePHYErAAAAAHLLbdeQZcflOZUWx7tUjK25yCHx',
        });
        const payload = ticket.getPayload();
        const userId = payload['sub'];

        // Autenticación local (mock)
        const user = usuarios.find(u => u.usuario === payload.email);
        if (!user || user.contrasena !== payload.somePasswordField) {
            return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
        }

        //Devuelve el correo en la respuesta
        res.json({ "success": true, "email": payload.email });

        // Todo salió bien
        res.json({ success: true, userId });
    } catch (error) {
        console.error('Error en autenticación:', error.message);
        res.status(500).json({ success: false, message: 'Error al autenticar.' });
    }
});
document.getElementById('logoutButton').addEventListener('click', function() {
    // Elimina los datos del usuario almacenados
    localStorage.removeItem('1234'); // Cambia 'userEmail' por la clave que usaste
    localStorage.removeItem('authToken'); // Si usas un token, elimínalo también

    // Redirige al usuario a la página de inicio de sesión
    window.location.href = '/Oauthproyect/index.html?_ijt=upnvii537074dfl496i9tmt0ib&_ij_reload=RELOAD_ON_SAVE';
});


const user = usuarios.find(u => u.usuario === usuario);
if (!user || user.contrasena !== contrasena) {
    return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
}
res.json({ success: true, message: '¡Autenticación exitosa!' });


//Endpoint para recibir el token y validarlo con Google
const usuarios = [{ usuario: 'admin', contrasena: '1234' }];

app.listen(3003, () => console.log('Servidor en http://localhost:3003'));


const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client('480610804915-0r21gu8krs2di8jcs6k2g6q0vdkocbnn.apps.googleusercontent.com');

// Endpoint para recibir el token de Google y verificarlo
async function verify(token) {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: '6LePHYErAAAAAHLLbdeQZcflOZUWx7tUjK25yCHx',
    });
    return ticket.getPayload();
}