if (!process.env.MONGO_URI) throw new Error("Database envs are not available.");
if (!process.env.JWT_SECRET) throw new Error("JWT envs are not available.");
if (
  !process.env.BREVO_SMTP_USER ||
  !process.env.BREVO_SMTP_PASS ||
  !process.env.SENDER_EMAIL
)
  throw new Error("Email envs are not available.");
if (!process.env.PORT) throw new Error("Server's port is not available.");
if (!process.env.NODE_ENV) throw new Error("Node env is not available.");
if (!process.env.APP_URL) throw new Error("App url is not available.");
if (
  !process.env.GOOGLE_CLIENT_ID ||
  !process.env.GOOGLE_CLIENT_SECRET ||
  !process.env.GOOGLE_REDIRECT_URI
)
  throw new Error("Google Oauth envs are missing");

const config = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  BREVO_SMTP_USER: process.env.BREVO_SMTP_USER,
  BREVO_SMTP_PASS: process.env.BREVO_SMTP_PASS,
  SENDER_EMAIL: process.env.SENDER_EMAIL,
  NODE_ENV: process.env.NODE_ENV,
  APP_URL: process.env.APP_URL,
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
};

export default config;
