import mongoose from "mongoose";
import { app } from "./app.js";
import { env } from "./config/env.js";
import { logger } from "./utils/logger.js";

await mongoose.connect(env.MONGO_URI);
// TTL + unique indexes are created automatically on first start (autoIndex).
// On a large production DB, create them through a controlled migration instead.

const server = app.listen(env.PORT, () => logger.info(`API listening on :${env.PORT}`));

// Graceful shutdown: finish in-flight requests, then close the DB.
function shutdown(signal) {
  logger.info(`${signal} received, shutting down`);
  server.close(async () => {
    await mongoose.disconnect();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("unhandledRejection", (err) => logger.error({ err }, "unhandledRejection"));
