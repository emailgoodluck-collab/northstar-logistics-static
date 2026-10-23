import "dotenv/config";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";
import { Pool } from "pg";
import { migrate } from "./database.js";
import { createSessionToken, hashPassword, hashToken, verifyPassword } from "./security.js";
import { ValidationError, validateAllocation, validateDriver, validateShipment } from "./validation.js";

const SESSION_COOKIE = "northstar_admin";
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const RESOURCE_CONFIG = {
  shipments: {
    table: "shipments",
    fields: ["tracking_code", "origin", "destination", "mode", "status", "eta", "progress"],
    validate: validateShipment,
  },
  drivers: {
    table: "drivers",
    fields: ["name", "region", "status", "vehicle", "load_description"],
    validate: validateDriver,
  },
  allocations: {
    table: "allocations",
    fields: ["region", "assigned", "utilization", "focus"],
    validate: validateAllocation,
  },
};

const rootDir = fileURLToPath(new URL("../", import.meta.url));
const loginAttempts = new Map();
const trackingAttempts = new Map();
const supportAttempts = new Map();

function cookieValue(req, name) {
  const prefix = `${name}=`;
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const value = part.trim();
    if (value.startsWith(prefix)) return value.slice(prefix.length);
  }
  return "";
}

function setSessionCookie(res, token, secure) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DURATION_MS / 1000}${secure ? "; Secure" : ""}`,
  );
}

function clearSessionCookie(res, secure) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`,
  );
}

function checkRateLimit(store, key, maxAttempts, windowMs) {
  const now = Date.now();
  const attempts = store.get(key);
  if (!attempts || now - attempts.firstAttemptAt >= windowMs) {
    store.set(key, { firstAttemptAt: now, count: 1 });
  } else {
    attempts.count += 1;
    if (attempts.count > maxAttempts) return true;
  }
  if (store.size > 5000) {
    for (const [storedKey, value] of store) {
      if (now - value.firstAttemptAt >= windowMs) store.delete(storedKey);
    }
  }
  return false;
}

function checkLoginLimit(key) {
  return checkRateLimit(loginAttempts, key, MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW_MS);
}

function setPublicCors(app, allowedOrigin) {
  if (!allowedOrigin) return;
  for (const route of ["/api/dashboard", "/api/track", "/api/support"]) {
    app.use(route, (req, res, next) => {
      const origin = req.get("Origin");
      if (!origin) return next();
      if (origin !== allowedOrigin) {
        return res.status(403).json({ error: "Origin is not allowed." });
      }
      res.set("Access-Control-Allow-Origin", allowedOrigin);
      res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
      res.set("Vary", "Origin");
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    });
  }
}

function bearerToken(req) {
  const value = req.get("Authorization") ?? "";
  const match = /^Bearer ([a-f0-9]{64})$/i.exec(value);
  return match?.[1] ?? "";
}

function validateSupportMessage(value) {
  if (typeof value !== "string" || !value.trim() || value.trim().length > 2000) {
    throw new ValidationError("Message must contain 1 to 2000 characters.");
  }
  return value.trim();
}

function checkSupportLimit(key) {
  return checkRateLimit(supportAttempts, key, 20, 5 * 60_000);
}

async function recordEvent(pool, adminId, action, entity, entityId = null) {
  await pool.query(
    "INSERT INTO operation_events (id, admin_id, action, entity, entity_id) VALUES ($1, $2, $3, $4, $5)",
    [randomUUID(), adminId, action, entity, entityId],
  );
}

async function recordShipmentHistory(client, shipmentId, status, progress, description) {
  await client.query(
    `INSERT INTO shipment_tracking_events (id, shipment_id, status, progress, description)
     VALUES ($1, $2, $3, $4, $5)`,
    [randomUUID(), shipmentId, status, progress, description],
  );
}

async function withAudit(pool, adminId, action, entity, entityId, operation) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await operation(client);
    await recordEvent(client, adminId, action, entity, entityId);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function createApp(pool, options = {}) {
  const app = express();
  const secureCookies = options.secureCookies ?? process.env.NODE_ENV === "production";
  const allowedOrigin = options.allowedOrigin ?? process.env.STATIC_SITE_ORIGIN ?? "";
  app.disable("x-powered-by");
  if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
  app.use((req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "DENY");
    res.set("Referrer-Policy", "same-origin");
    next();
  });
  app.use(express.json({ limit: "16kb" }));
  setPublicCors(app, allowedOrigin);

  app.get("/health/live", (_req, res) => res.json({ status: "ok", service: "northstar-logistics" }));
  app.get("/health/ready", async (_req, res) => {
    await pool.query("SELECT 1");
    res.json({ status: "ready", database: "connected" });
  });

  app.get("/api/dashboard", async (_req, res) => {
    const [shipmentCounts, driverCounts, allocations] = await Promise.all([
      pool.query(
        "SELECT COUNT(*)::int AS total, COUNT(CASE WHEN status <> 'Delivered' THEN 1 END)::int AS active FROM shipments",
      ),
      pool.query(
        "SELECT COUNT(*)::int AS total, COUNT(CASE WHEN status IN ('Available', 'On route', 'Break') THEN 1 END)::int AS online FROM drivers",
      ),
      pool.query("SELECT region, assigned, utilization, focus FROM allocations ORDER BY region"),
    ]);
    res.json({
      generatedAt: new Date().toISOString(),
      summary: {
        activeShipments: shipmentCounts.rows[0].active,
        totalShipments: shipmentCounts.rows[0].total,
        driversOnline: driverCounts.rows[0].online,
        totalDrivers: driverCounts.rows[0].total,
      },
      allocations: allocations.rows,
    });
  });

  app.get("/api/track/:trackingCode", async (req, res) => {
    if (checkRateLimit(trackingAttempts, req.ip, 60, 60_000)) {
      res.set("Retry-After", "60");
      return res.status(429).json({ error: "Too many tracking requests. Try again in one minute." });
    }
    const trackingCode = String(req.params.trackingCode).toUpperCase();
    const result = await pool.query(
      `SELECT id, tracking_code, origin, destination, mode, status, eta, progress, created_at, updated_at
       FROM shipments WHERE tracking_code = $1`,
      [trackingCode],
    );
    if (!result.rowCount) return res.status(404).json({ error: "Shipment not found." });
    const shipment = result.rows[0];
    const history = await pool.query(
      `SELECT status, progress, description, occurred_at
       FROM shipment_tracking_events
       WHERE shipment_id = $1
       ORDER BY occurred_at DESC`,
      [shipment.id],
    );
    return res.json({
      ...shipment,
      trackingHistory: history.rows,
      checkedAt: new Date().toISOString(),
    });
  });

  app.post("/api/support/conversations", async (req, res) => {
    if (checkRateLimit(supportAttempts, `new:${req.ip}`, 5, 10 * 60_000)) {
      res.set("Retry-After", "600");
      return res.status(429).json({ error: "Too many new conversations. Please try again later." });
    }
    const message = validateSupportMessage(req.body?.message);
    const conversationId = randomUUID();
    const accessToken = createSessionToken();
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "INSERT INTO support_conversations (id, access_token_hash) VALUES ($1, $2)",
        [conversationId, hashToken(accessToken)],
      );
      await client.query(
        `INSERT INTO support_messages (id, conversation_id, sender_kind, body)
         VALUES ($1, $2, 'customer', $3)`,
        [randomUUID(), conversationId, message],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return res.status(201).json({ conversationId, accessToken });
  });

  app.get("/api/support/conversations/:id/messages", async (req, res) => {
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: "A valid conversation token is required." });
    const conversation = await pool.query(
      "SELECT id, status FROM support_conversations WHERE id = $1 AND access_token_hash = $2",
      [req.params.id, hashToken(token)],
    );
    if (!conversation.rowCount) return res.status(404).json({ error: "Support conversation not found." });
    const messages = await pool.query(
      `SELECT id, sender_kind, body, created_at FROM support_messages
       WHERE conversation_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [req.params.id],
    );
    return res.json({ status: conversation.rows[0].status, messages: messages.rows.reverse() });
  });

  app.post("/api/support/conversations/:id/messages", async (req, res) => {
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: "A valid conversation token is required." });
    const tokenHash = hashToken(token);
    if (checkSupportLimit(tokenHash)) {
      res.set("Retry-After", "300");
      return res.status(429).json({ error: "Too many messages. Please try again later." });
    }
    const message = validateSupportMessage(req.body?.message);
    const client = await pool.connect();
    let result;
    try {
      await client.query("BEGIN");
      const conversation = await client.query(
        "SELECT id, status FROM support_conversations WHERE id = $1 AND access_token_hash = $2 FOR UPDATE",
        [req.params.id, tokenHash],
      );
      if (!conversation.rowCount) {
        const error = new Error("Support conversation not found.");
        error.status = 404;
        throw error;
      }
      if (conversation.rows[0].status !== "open") {
        const error = new Error("This support conversation is closed.");
        error.status = 409;
        throw error;
      }
      result = await client.query(
        `INSERT INTO support_messages (id, conversation_id, sender_kind, body)
         VALUES ($1, $2, 'customer', $3) RETURNING id, sender_kind, body, created_at`,
        [randomUUID(), req.params.id, message],
      );
      await client.query("UPDATE support_conversations SET updated_at = NOW() WHERE id = $1", [req.params.id]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    return res.status(201).json(result.rows[0]);
  });

  app.get("/admin", (_req, res) => res.sendFile(path.join(rootDir, "admin.html")));

  app.get("/api/admin/session", async (req, res) => {
    const token = cookieValue(req, SESSION_COOKIE);
    if (!/^[a-f0-9]{64}$/i.test(token)) return res.json({ authenticated: false });
    const result = await pool.query(
      `SELECT users.id, users.email
       FROM admin_sessions sessions
       JOIN admin_users users ON users.id = sessions.admin_id
       WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()`,
      [hashToken(token)],
    );
    if (!result.rowCount) return res.json({ authenticated: false });
    return res.json({ authenticated: true, admin: result.rows[0] });
  });

  app.post("/api/admin/session", async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!email || !password) return res.status(400).json({ error: "Email and password are required." });
    const limitKey = `${req.ip}:${email}`;
    if (checkLoginLimit(limitKey)) {
      return res.status(429).json({ error: "Too many sign-in attempts. Try again in 15 minutes." });
    }
    await pool.query("DELETE FROM admin_sessions WHERE expires_at < NOW()");
    const userResult = await pool.query(
      "SELECT id, email, password_hash FROM admin_users WHERE LOWER(email) = $1",
      [email],
    );
    const user = userResult.rows[0];
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    const token = createSessionToken();
    await pool.query(
      "INSERT INTO admin_sessions (token_hash, admin_id, expires_at) VALUES ($1, $2, $3)",
      [hashToken(token), user.id, new Date(Date.now() + SESSION_DURATION_MS).toISOString()],
    );
    loginAttempts.delete(limitKey);
    setSessionCookie(res, token, secureCookies);
    return res.json({ admin: { id: user.id, email: user.email } });
  });

  app.delete("/api/admin/session", async (req, res) => {
    const token = cookieValue(req, SESSION_COOKIE);
    if (/^[a-f0-9]{64}$/i.test(token)) {
      await pool.query("DELETE FROM admin_sessions WHERE token_hash = $1", [hashToken(token)]);
    }
    clearSessionCookie(res, secureCookies);
    return res.status(204).end();
  });

  async function requireAdmin(req, res, next) {
    const token = cookieValue(req, SESSION_COOKIE);
    if (!/^[a-f0-9]{64}$/i.test(token)) return res.status(401).json({ error: "Sign-in required." });
    const result = await pool.query(
      `SELECT users.id, users.email
       FROM admin_sessions sessions
       JOIN admin_users users ON users.id = sessions.admin_id
       WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()`,
      [hashToken(token)],
    );
    if (!result.rowCount) return res.status(401).json({ error: "Session expired. Sign in again." });
    req.admin = result.rows[0];
    return next();
  }

  const adminApi = express.Router();
  adminApi.use(requireAdmin);

  for (const [resource, config] of Object.entries(RESOURCE_CONFIG)) {
    const columns = ["id", ...config.fields, "created_at", "updated_at"].join(", ");
    adminApi.get(`/${resource}`, async (_req, res) => {
      const result = await pool.query(`SELECT ${columns} FROM ${config.table} ORDER BY created_at DESC`);
      res.json(result.rows);
    });

    adminApi.post(`/${resource}`, async (req, res) => {
      const value = config.validate(req.body);
      const id = randomUUID();
      const columns = ["id", ...config.fields];
      const placeholders = columns.map((_, index) => `$${index + 1}`).join(", ");
      const values = [id, ...config.fields.map((field) => value[field])];
      const result = await withAudit(pool, req.admin.id, "created", resource, id, async (client) => {
        const created = await client.query(
          `INSERT INTO ${config.table} (${columns.join(", ")}) VALUES (${placeholders}) RETURNING *`,
          values,
        );
        if (resource === "shipments") {
          await recordShipmentHistory(
            client,
            id,
            created.rows[0].status,
            created.rows[0].progress,
            `Shipment created with status ${created.rows[0].status}.`,
          );
        }
        return created;
      });
      res.status(201).json(result.rows[0]);
    });

    adminApi.patch(`/${resource}/:id`, async (req, res) => {
      const result = await withAudit(pool, req.admin.id, "updated", resource, req.params.id, async (client) => {
        const existingResult = await client.query(
          `SELECT ${columns} FROM ${config.table} WHERE id = $1 FOR UPDATE`,
          [req.params.id],
        );
        if (!existingResult.rowCount) {
          const error = new Error("Record not found.");
          error.status = 404;
          throw error;
        }
        const existing = existingResult.rows[0];
        const merged = {
          ...Object.fromEntries(config.fields.map((field) => [field, existing[field]])),
          ...req.body,
        };
        const value = config.validate(merged);
        const assignments = config.fields.map((field, index) => `${field} = $${index + 2}`).join(", ");
        const values = [req.params.id, ...config.fields.map((field) => value[field])];
        const updated = await client.query(
          `UPDATE ${config.table} SET ${assignments}, updated_at = NOW() WHERE id = $1 RETURNING *`,
          values,
        );
        if (resource === "shipments") {
          const current = updated.rows[0];
          const changes = [];
          if (existing.status !== current.status) {
            changes.push(`status changed from ${existing.status} to ${current.status}`);
          }
          if (existing.progress !== current.progress) {
            changes.push(`progress updated from ${existing.progress}% to ${current.progress}%`);
          }
          if (new Date(existing.eta).getTime() !== new Date(current.eta).getTime()) {
            changes.push("ETA updated");
          }
          for (const field of ["origin", "destination", "mode"]) {
            if (existing[field] !== current[field]) changes.push(`${field} updated`);
          }
          if (changes.length) {
            await recordShipmentHistory(
              client,
              req.params.id,
              current.status,
              current.progress,
              `${changes.join("; ")}.`,
            );
          }
        }
        return updated;
      });
      return res.json(result.rows[0]);
    });

    adminApi.delete(`/${resource}/:id`, async (req, res) => {
      const result = await withAudit(pool, req.admin.id, "deleted", resource, req.params.id, (client) =>
        client.query(`DELETE FROM ${config.table} WHERE id = $1 RETURNING id`, [req.params.id]),
      );
      if (!result.rowCount) return res.status(404).json({ error: "Record not found." });
      return res.status(204).end();
    });
  }

  adminApi.get("/events", async (_req, res) => {
    const result = await pool.query(
      `SELECT events.id, events.action, events.entity, events.entity_id, events.occurred_at, users.email AS admin_email
       FROM operation_events events
       LEFT JOIN admin_users users ON users.id = events.admin_id
       ORDER BY events.occurred_at DESC
       LIMIT 100`,
    );
    res.json(result.rows);
  });

  adminApi.get("/support/conversations", async (_req, res) => {
    const result = await pool.query(
      `SELECT id, status, created_at, updated_at
       FROM support_conversations
       ORDER BY updated_at DESC
       LIMIT 100`,
    );
    const conversations = await Promise.all(result.rows.map(async (conversation) => {
      const message = await pool.query(
        `SELECT body FROM support_messages WHERE conversation_id = $1
         ORDER BY created_at DESC LIMIT 1`,
        [conversation.id],
      );
      return { ...conversation, last_message: message.rows[0]?.body ?? "" };
    }));
    res.json(conversations);
  });

  adminApi.get("/support/conversations/:id/messages", async (req, res) => {
    const conversation = await pool.query(
      "SELECT id, status FROM support_conversations WHERE id = $1",
      [req.params.id],
    );
    if (!conversation.rowCount) return res.status(404).json({ error: "Support conversation not found." });
    const messages = await pool.query(
      `SELECT id, sender_kind, body, created_at FROM support_messages
       WHERE conversation_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [req.params.id],
    );
    return res.json({ status: conversation.rows[0].status, messages: messages.rows.reverse() });
  });

  adminApi.post("/support/conversations/:id/messages", async (req, res) => {
    const message = validateSupportMessage(req.body?.message);
    const result = await withAudit(pool, req.admin.id, "replied", "support conversation", req.params.id, async (client) => {
      const conversation = await client.query(
        "SELECT id, status FROM support_conversations WHERE id = $1 FOR UPDATE",
        [req.params.id],
      );
      if (!conversation.rowCount) {
        const error = new Error("Support conversation not found.");
        error.status = 404;
        throw error;
      }
      if (conversation.rows[0].status !== "open") {
        const error = new Error("This support conversation is closed.");
        error.status = 409;
        throw error;
      }
      const reply = await client.query(
        `INSERT INTO support_messages (id, conversation_id, sender_kind, sender_id, body)
         VALUES ($1, $2, 'admin', $3, $4) RETURNING id, sender_kind, body, created_at`,
        [randomUUID(), req.params.id, req.admin.id, message],
      );
      await client.query("UPDATE support_conversations SET updated_at = NOW() WHERE id = $1", [req.params.id]);
      return reply;
    });
    return res.status(201).json(result.rows[0]);
  });

  app.use("/api/admin", adminApi);

  app.use(express.static(rootDir, { index: "index.html", maxAge: "1h" }));
  app.use("/api", (_req, res) => res.status(404).json({ error: "API route not found." }));
  app.use((_req, res) => res.status(404).type("text/plain").send("Not found"));
  app.use((error, _req, res, _next) => {
    if (error instanceof ValidationError) return res.status(error.status).json({ error: error.message });
    if (error.status === 404) return res.status(404).json({ error: error.message });
    if (error.status === 409) return res.status(409).json({ error: error.message });
    if (error?.code === "23505") return res.status(409).json({ error: "A record with this unique value already exists." });
    if (error?.type === "entity.parse.failed") return res.status(400).json({ error: "Request body must contain valid JSON." });
    console.error("NorthStar request failed:", error);
    return res.status(500).json({ error: "The request could not be completed." });
  });

  return app;
}

export async function initializeDatabase(pool, { adminEmail, adminPassword }) {
  await migrate(pool);
  if (!adminEmail && !adminPassword) return;
  if (!adminEmail || !adminPassword || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
    throw new Error("Set a valid BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD together.");
  }
  if (adminPassword.length < 12) {
    throw new Error("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.");
  }
  const passwordHash = await hashPassword(adminPassword);
  await pool.query(
    "INSERT INTO admin_users (id, email, password_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    [randomUUID(), adminEmail.trim().toLowerCase(), passwordHash],
  );
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  if (process.env.NODE_ENV === "production"
    && (!process.env.BOOTSTRAP_ADMIN_EMAIL || !process.env.BOOTSTRAP_ADMIN_PASSWORD)) {
    throw new Error("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required in production.");
  }
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  pool.on("error", (error) => console.error("Database pool error:", error));
  try {
    await initializeDatabase(pool, {
      adminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL,
      adminPassword: process.env.BOOTSTRAP_ADMIN_PASSWORD,
    });
    const app = await createApp(pool);
    const port = Number.parseInt(process.env.PORT ?? "3000", 10);
    const server = app.listen(port, "0.0.0.0", () => {
      console.log(`NorthStar Logistics API listening on port ${port}`);
    });
    const shutdown = () => {
      server.close((error) => {
        if (error) {
          console.error("Failed to close HTTP server:", error);
          process.exitCode = 1;
        }
        void pool.end();
      });
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (error) {
    await pool.end();
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
