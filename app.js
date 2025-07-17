// app.js
const express = require('express');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors()); // Permite peticiones desde el frontend


//Endpoint para recibir el token y validarlo con Google
const usuarios = [{ usuario: 'admin', contrasena: '1234' }];


app.post('/api/auth/login', (req, res) => {
    const { usuario, contrasena, recaptchaToken } = req.body;
    if (!usuario || !contrasena || !recaptchaToken) {
        return res.status(400).json({ success: false, message: 'Datos incompletos.' });
    }
    const user = usuarios.find(u => u.usuario === usuario);
    if (!user || user.contrasena !== contrasena) {
        return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
    }
    res.json({ success: true, message: '¡Autenticación exitosa!' });
});

app.listen(3003, () => console.log('Servidor en http://localhost:3003'));

const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client('480610804915-0r21gu8krs2di8jcs6k2g6q0vdkocbnn.apps.googleusercontent.com');

app.post('/api/auth/google', async (req, res) => {
    const { token } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: '480610804915-0r21gu8krs2di8jcs6k2g6q0vdkocbnn.apps.googleusercontent.com',
        });
        const payload = ticket.getPayload();
        const userId = payload['sub'];
        // Aquí puedes buscar o registrar al usuario en tu base de datos
        res.json({ success: true, userId });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Token inválido' });
    }
});