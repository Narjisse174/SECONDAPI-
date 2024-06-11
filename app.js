const fastify = require('fastify')();
const tokenRoutes = require('./modules/routes/routes');

fastify.register(tokenRoutes);

const start = async () => {
    try {
        await fastify.listen(3000);
        console.log('Server running on port 3000');
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();
