const pino = require('pino')
const logger = pino({
  level: 'info',
  genReqId: () => String(Date.now()),
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true
    }
  }
})
const fastify = require('fastify')({logger:logger})
const fastifyCors  = require('@fastify/cors')
const dotenv = require("dotenv");
dotenv.config();

const originURL = process.env.environment === 'production' ? '' : process.env.developmentOriginUrl
fastify.register(fastifyCors , {
  // origin: '*',
  origin: originURL,
  credentials: true, // Enable credentials (cookies)
  methods: ['GET', 'POST', 'PUT', 'DELETE']
})

const fastifyCookie = require('@fastify/cookie');
fastify.register(fastifyCookie);



// Declare a route
fastify.get('/', function (request, reply) {
  reply.send("Hello World")
})

// healthcheck
fastify.get('/healthz', function (request, reply) {
  reply.code(200).send("Hello World")
})

fastify.register(require("./routes"));

// Run the server!
const port = process.env.PORT || 4000;
const startServer = async () => {
    try {
      await fastify.listen(port);
      fastify.log.info(`server listening on ${port}`);
    } catch (err) {
      fastify.log.error(err);
      process.exit(1);
    }
};

startServer()