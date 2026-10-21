import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { env, clientOrigins } from "./config/env.js";
import { AppError } from "./utils/AppError.js";
import authRoutes from "./routes/auth.routes.js";
import { globalLimiter } from "./middleware/rateLimit.js";
import { notFound, errorHandler } from "./middleware/errorHandler.js";

export const app = express();
app.disable("x-powered-by");

// Behind nginx / a load balancer, set TRUST_PROXY=1 so req.ip is the REAL client IP.
// A wrong value breaks rate limiting (everyone looks like the proxy's IP).
app.set("trust proxy", env.TRUST_PROXY);

// Security headers. HSTS tells browsers "HTTPS only" for 2 years.
app.use(
  helmet({
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  }),
);


// you never call origin(...) yourself. Express calls the cors() middleware, which reads req.headers.origin and invokes your function with it.
app.use(
  cors({
    // credentials:true REQUIRES an exact origin list ("*" is rejected by browsers).
    origin(origin, cb) {
      if (!origin || clientOrigins.includes(origin)) return cb(null, true);
      cb(new AppError(403, "CORS", "Origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "DELETE" , "PUT", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 600,//Lets browsers cache the preflight permission for up to 600 seconds (10 minutes).
  }),
);

app.use(express.json({ limit: "10kb" })); // small body cap = cheap DoS protection
app.use(cookieParser());
app.use("/api", globalLimiter);

app.get("/health", (_req, res) => res.json({ ok: true })); //Just for checking whether the backend is working fine or broken.
app.use("/api/auth", authRoutes);

app.use(notFound);
app.use(errorHandler);


// Because Express route handlers only catch errors that happen during the lifecycle of the HTTP request, any error thrown after the response has been sent will bubble up uncaught. In Node.js, an uncaught exception or an unhandled promise rejection will crash your entire server process unless you explicitly handle it.