const { generateToken, isTokenValidAndNotExpired, renewToken, authenticateToken } = require('../controllers/controllers');

async function tokenRoute(fastify, _options) {
    fastify.get('/generate-token', generateToken);

    fastify.get('/verify-token', async (request, reply) => {
        const { token } = request.query;
        if (!token) {
            return reply.code(400).send({ error: 'Token manquant dans les paramètres de la requête.' });
        }
        try {
            const { isValid, isExpired, timeLeft } = await isTokenValidAndNotExpired(token);
            if (isValid) {
                reply.send({ isValid, isExpired, timeLeft });
            } else if (isExpired) {
                const newToken = await renewToken(token);
                reply.send({ isValid: false, isExpired: true, newToken });
            } else {
                reply.send({ isValid: false, isExpired: false, timeLeft });
            }
        } catch (error) {
            reply.code(401).send({ error: error.message });
        }
    });

    fastify.get('/data', { preHandler: authenticateToken }, async (request, reply) => {
        const userData = {
            exp: request.user.exp,
            role: request.user.role,
            app_name: request.user.app_name,
            app_url: request.user.app_url,
            userId: request.user.userId,
            iat: request.user.iat
        };
        reply.send({ message: 'Accès autorisé aux données sécurisées', user: userData });
    });
}

module.exports = tokenRoute;
