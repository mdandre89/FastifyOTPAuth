const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {db} = require('./../connection/pg')
const crypto = require('crypto');
const { encode } = require('hi-base32');
const OTPAuth = require('otpauth');

// Configure JWT secret
const JWT_SECRET = process.env.JWTsecret

const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer, 'Crockford');
  return base32;
};
// Middleware for authenticating JWT token
const authenticateToken = async (request, reply) => {
  const token = request.cookies.auth_token;
  // check that there is a token and it matches the one issued to that user in the past
  if (!token) {
    return reply.status(401).send({ error: 'Authentication token not provided' });
  }

  await jwt.verify(token, JWT_SECRET, async (err, decodedToken) => {
    if (err) {
      return reply.status(403).send({ error: 'Invalid token' });
    }
    const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1 AND token = $2 AND random_hash=$3', [decodedToken.userId, token, decodedToken.random_hash]);
    if(user){

      // if MFA is enabled then need to check the token matches

      request.decodedToken = decodedToken;
      request.user = user

      // await next();
    }else{
      return reply.status(401).send({
        status: "fail",
        message: "Invalid credentials.",
      });
    }
  });
}

// Middleware for verifying MFA code
async function mfaVerification(request, reply, next) {
  const { mfaCode } = request.body;
  
  const token = request.cookies.auth_token;;
  const decodedToken = await jwt.verify(token, JWT_SECRET);
  const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [decodedToken.userId]);

  if (!user) {
    return reply.status(401).send({ error: 'Invalid user' });
  }

  const verified = totp.verify({
    secret: user.mfaSecret.base32,
    encoding: 'base32',
    token: mfaCode,
  });

  if (!verified) {
    return reply.status(401).send({ error: 'Invalid MFA code' });
  }
}

const login = async (request, reply) => {
  console.log('login')
  try {
    const {email, password } = request.body;
    // Fetch the user from the database
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);

    if (user) {
      // Compare passwords
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        // Create a JWT token
        const token = jwt.sign({ userId: user.id, random_hash: user.random_hash}, JWT_SECRET, {expiresIn: '24h'});

        await db.query('UPDATE users SET token = $1 WHERE id = $2', [token, user.id]);

        const {name, otp_enabled, otp_verified, email, id} = user

        reply
        .setCookie('auth_token', token, { domain: '127.0.0.1', path: '/', sameSite: 'None', secure: true  } )
        .send({ success: true, message: 'Login successful', token, name, otp_enabled, otp_verified, email, id});
      } else {
        reply.status(401).send({ success: false, message: 'Invalid credentials.' });
      }
    } else {
      reply.status(401).send({ success: false, message: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    reply.status(500).send({ success: false, message: 'Error during login.' });
  }
}

const logout = async (request, reply) => {
  try {
    console.log("logout", request.user)
    await db.query('UPDATE users SET token = $1 WHERE id = $2', [null, request.user.id]);
    // Clear the token from client-side storage
    reply.clearCookie('auth_token', { path: '/' }).send({ success: true, message: 'Logout successful' });
  
    // Redirect or send a response indicating successful logout
    reply.redirect('/login');

  } catch (error) {
    console.error('Error during login:', error);
    reply.status(500).send({ success: false, message: 'Error during login.' });
  }
}

const register = async (request, reply) => {
  try {
    const { email, name, password } = request.body;
    // Check if the user already exists
    const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);

    if (existingUser) {
      reply.status(409).send({ success: false, message: 'A user with that email already exists.' });
    } else {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
      const random_hash = crypto.randomBytes(Math.ceil(20 / 2)).toString('hex').slice(0, 20);

      // Insert the user into the database
      await db.none('INSERT INTO users (email, name, password, random_hash) VALUES ($1, $2, $3, $4)', [email, name, hashedPassword, random_hash]);

      reply.send({ success: true, message: 'User registered successfully.' });
    }
  } catch (error) {
    console.error('Error during registration:', error);
    reply.status(500).send({ success: false, message: 'Error during registration.' });
  }
};

const updatePassword = async (request, reply) => {
  try {
    const {  currentPassword, newPassword } = request.body;
    if (request.user) {
      // Compare passwords
      const isPasswordValid = await bcrypt.compare(currentPassword, request.user.password);

      if (isPasswordValid) {
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database
        await db.none('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, request.decodedToken.userId]);

        reply.send({ success: true, message: 'Password updated successfully.' });
      } else {
        reply.status(401).send({ success: false, message: 'Invalid credentials.' });
      }
    } else {
      reply.status(401).send({ success: false, message: 'Invalid credentials.' });
    }
  } catch (error) {
    console.error('Error during password update:', error);
    reply.status(500).send({ success: false, message: 'Error during password update.' });
  }
};

// OTP handling
const GenerateOTP = async (request, reply) => {
  try {
    if (!request.user) {
      return reply.status(404).send({
        status: "fail",
        message: "No user with that email exists",
      });
    }

    const base32_secret = generateRandomBase32();

    let totp = new OTPAuth.TOTP({
      issuer: "random_name.com",
      label: "random_name",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: base32_secret,
    });

    let otpauth_url = totp.toString();

    await db.query('UPDATE users SET otp_auth_url = $1, otp_base32 = $2 WHERE id = $3', [otpauth_url, base32_secret, request.decodedToken.userId]);

    reply.status(200).send({
      base32: base32_secret,
      otpauth_url,
    });
  } catch (error) {
    reply.status(500).send({
      status: "error",
      message: error.message,
    });
  }
};

const VerifyOTP = async (request, reply) => {
  try {
    const tokenToVerify = request.body.token;
    const message = "Token is invalid or user doesn't exist";

    if (!request.user) {
      return reply.status(401).send({
        status: "fail",
        message,
      });
    }

    let totp = new OTPAuth.TOTP({
      issuer: "random_name.com",
      label: "random_name",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: request.user.otp_base32,
    });

    let delta = totp.validate({ token: tokenToVerify });
    if (delta === null) {
      return reply.status(401).send({
        status: "fail",
        message,
      });
    }
    await db.oneOrNone('UPDATE users SET otp_enabled = $1, otp_verified = $2 WHERE id = $3', [true, true, request.decodedToken.userId]);
    const updatedUser = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [request.decodedToken.userId]);

    reply.status(200).send({
      otp_verified: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        otp_enabled: updatedUser.otp_enabled,
        otp_verified: updatedUser.otp_verified,
      },
    });
  } catch (error) {
    reply.status(500).send({
      status: "error",
      message: error.message,
    });
  }
};

const ValidateOTP = async (request, reply) => {
  try {
    const tokenToVerify  = request.body.token;
    console.log("ValidateOTP")

    const message = "Token is invalid or user doesn't exist";
    if (!request.user) {
      return reply.status(401).send({
        status: "fail",
        message,
      });
    }
    let totp = new OTPAuth.TOTP({
      issuer: "random.com",
      label: "random",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: request.user.otp_base32,
    });

    let delta = totp.validate({ token: tokenToVerify });

    if (delta === null) {
      return reply.status(401).send({
        status: "fail",
        message,
      });
    }

    // Generate a new JWT
    // let totp = new OTPAuth.TOTP({
    //   issuer: "random_name.com",
    //   label: "random_name",
    //   algorithm: "SHA1",
    //   digits: 6,
    //   period: 30,
    //   secret: request.user.otp_base32,
    // });

    // const otp = totp.generate(6, { digits: true, alphabets: false, upperCase: false });
    // const token = jwt.sign({ userId: user.id, random_hash: user.random_hash }, JWT_SECRET, {expiresIn: '24h'});

    // await db.query('UPDATE users SET token = $1 WHERE id = $2', [token, user.id]);


    reply.status(200).send({
      otp_valid: true,
    });
  } catch (error) {
    reply.status(500).send({
      status: "error",
      message: error.message,
    });
  }
};

const DisableOTP = async (request, reply) => {
  try {
    // const token = request.cookies.auth_token;;
    // const decodedToken = jwt.verify(token, JWT_SECRET);
    // const user = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [decodedToken.userId]);

    if (!request.user) {
      return reply.status(401).send({
        status: "fail",
        message: "User doesn't exist",
      });
    }

    await db.none('UPDATE users SET otp_enabled = $1, otp_verified = $2 WHERE id = $3', [false, false, request.decodedToken.userId]);
    const updatedUser = await db.oneOrNone('SELECT * FROM users WHERE id = $1', [request.decodedToken.userId]);

    reply.status(200).send({
      otp_disabled: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        otp_enabled: updatedUser.otp_enabled,
        otp_verified: updatedUser.otp_verified,
      },
    });
  } catch (error) {
    reply.status(500).send({
      status: "error",
      message: error.message,
    });
  }
};


module.exports = { authenticateToken, login, logout, register, updatePassword, GenerateOTP, VerifyOTP, ValidateOTP, DisableOTP};