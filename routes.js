const authController = require("./controllers/auth.controller");

async function routes(fastify, options) {
  fastify.post("/auth/login", authController.login);
  fastify.post("/auth/register", authController.register);
  fastify.put("/auth/update-password", { preHandler: [authController.authenticateToken], handler: authController.updatePassword});
  fastify.get("/auth/logout", { preHandler: [authController.authenticateToken] }, authController.logout);

  fastify.post("/auth/otp/generate", { preHandler: [authController.authenticateToken] }, authController.GenerateOTP);
  fastify.post("/auth/otp/verify", { preHandler: [authController.authenticateToken] }, authController.VerifyOTP);
  fastify.post("/auth/otp/validate", { preHandler: [authController.authenticateToken] }, authController.ValidateOTP);
  fastify.post("/auth/otp/disable", { preHandler: [authController.authenticateToken] }, authController.DisableOTP);
}

module.exports = routes;