require('dotenv').config();
const jwt = require('jsonwebtoken');
const axios = require('axios');

const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_API_URL = process.env.TOKEN_API_URL;
//Génerer le token
const generateToken = async (request, reply) => {
    try {
        const { expirate_date, role, app_name, app_url, userId } = request.query;

        const missingFields = [];
        if (!expirate_date) missingFields.push('expirate_date');
        if (!role) missingFields.push('role');
        if (!app_name) missingFields.push('app_name');
        if (!app_url) missingFields.push('app_url');
        if (!userId) missingFields.push('userId');

        if (missingFields.length > 0) {
            const errorMessage = `Les champs suivants sont manquants : ${missingFields.join(', ')}`;
            return reply.code(400).send({ error: errorMessage });
        }

        const expInSeconds = parseInt(expirate_date, 10);

        const payload = {
            exp: Math.floor(Date.now() / 1000) + expInSeconds,
            role,
            app_name,
            app_url,
            userId
        };

        const token = jwt.sign(payload, JWT_SECRET);

        return reply.send({ token, validFor: expInSeconds });
    } catch (error) {
        console.error(error);
        reply.code(500).send({ error: 'Internal Server Error' });
    }
};
//Vérifier si le token est valide et non expiré
const isTokenValidAndNotExpired = async (token) => {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const currentTime = Math.floor(Date.now() / 1000);
        const timeLeft = decoded.exp - currentTime;

        return { isValid: true, isExpired: false, timeLeft };
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return { isValid: false, isExpired: true, timeLeft: 0 };
        }
        return { isValid: false, isExpired: false, timeLeft: 0 };
    }
};

//Renouveler le token expiré
const renewToken = async (expiredToken) => {
    try {
        const decoded = jwt.decode(expiredToken);
        if (!decoded) {
            throw new Error('Token invalide');
        }

        const response = await axios.get(TOKEN_API_URL, {
            params: {
                expirate_date: 3600, 
                role: decoded.role,
                app_name: decoded.app_name,
                app_url: decoded.app_url,
                userId: decoded.userId
            }
        });

        if (response.status === 200 && response.data.token) {
            return response.data.token;
        } else {
            throw new Error('Échec du renouvellement du token');
        }
    } catch (error) {
        console.error(error);
        throw new Error('Impossible de renouveler le token');
    }
};
// Autoriser de recuperer de la donnée si seulement si authentifier
const authenticateToken = async (request, reply) => {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return reply.code(401).send({ error: 'Token manquant' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        request.user = decoded; // Ajouter les informations de l'utilisateur à la requête
    } catch (error) {
        return reply.code(403).send({ error: 'Token invalide ou expiré' });
    }
};
module.exports = { generateToken, isTokenValidAndNotExpired, renewToken, authenticateToken };
