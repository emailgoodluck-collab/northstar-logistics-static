import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { newDb } from "pg-mem";
import { createApp, initializeDatabase } from "../src/server.js";
import { hashPassword, verifyPassword } from "../src/security.js";
import { validateAllocation, validateDriver, validateShipment } from "../src/validation.js";

const ADMIN_EMAIL = "operations@example.com";
const ADMIN_PASSWORD = "local-test-password-2026";
const shipmentInput = {
  tracking_code: "EU-2147",
  origin: "Athens, Greece",
  destination: "Rotterdam, Netherlands",
  mode: "Road freight",
  status: "In transit",
  eta: "2026-10-24T12:30:00.000Z",
  progress: 74,
};

async function startTestServer() {
  const database = newDb();
  const { Pool } = database.adapters.createPg();
  const pool = new Pool();
  await initializeDatabase(pool, { adminEmail: ADMIN_EMAIL, adminPassword: ADMIN_PASSWORD });
  const app = await createApp(pool, { secureCookies: false, allowedOrigin: "https://northstar.example" });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  return {
    pool,
    server,
    url: `http://127.0.0.1:${address.port}`,
  };
}

async function adminLogin(url) {
  const response = await fetch(`${url}/api/admin/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  assert.equal(response.status, 200);
  return response.headers.get("set-cookie").split(";")[0];
}

test("password hashes verify without storing plaintext", async () => {
  const hash = await hashPassword("correct horse battery staple");
  assert.notEqual(hash, "correct horse battery staple");
  assert.equal(await verifyPassword("correct horse battery staple", hash), true);
  assert.equal(await verifyPassword("wrong password", hash), false);
  assert.equal(await verifyPassword("anything", "malformed"), false);
});

test("resource validators reject unknown keys and invalid field values", () => {
  assert.throws(() => validateShipment({ ...shipmentInput, owner_id: "attacker" }), /Unsupported field/);
  assert.throws(() => validateShipment({ ...shipmentInput, progress: 101 }), /progress/);
  assert.throws(() => validateDriver({ name: "", region: "Athens" }), /name/);
  assert.throws(() => validateAllocation({ region: "Greece", assigned: -1, utilization: 25, focus: "Port" }), /assigned/);
  assert.deepEqual(validateShipment(shipmentInput), shipmentInput);
});

test("admin APIs authenticate and persist shipments, drivers, allocations, and audit events", async (t) => {
  const context = await startTestServer();
  t.after(async () => {
    await new Promise((resolve, reject) => context.server.close((error) => error ? reject(error) : resolve()));
    await context.pool.end();
  });

  const { url } = context;
  const health = await fetch(`${url}/health/ready`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ready", database: "connected" });

  const adminPage = await fetch(`${url}/admin`);
  assert.equal(adminPage.status, 200);
  assert.match(await adminPage.text(), /Operations admin/);

  const publicBeforeLogin = await fetch(`${url}/api/admin/shipments`);
  assert.equal(publicBeforeLogin.status, 401);

  const allowedOrigin = await fetch(`${url}/api/dashboard`, {
    headers: { Origin: "https://northstar.example" },
  });
  assert.equal(allowedOrigin.headers.get("access-control-allow-origin"), "https://northstar.example");

  const deniedOrigin = await fetch(`${url}/api/dashboard`, {
    headers: { Origin: "https://untrusted.example" },
  });
  assert.equal(deniedOrigin.status, 403);

  const dashboardResponse = await fetch(`${url}/api/dashboard`);
  assert.equal(dashboardResponse.status, 200);
  assert.equal((await dashboardResponse.json()).summary.totalShipments, 0);

  const cookie = await adminLogin(url);
  const adminFetch = (route, options = {}) => fetch(`${url}${route}`, {
    ...options,
    headers: { Cookie: cookie, ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers },
  });

  const createdShipmentResponse = await adminFetch("/api/admin/shipments", {
    method: "POST",
    body: JSON.stringify(shipmentInput),
  });
  assert.equal(createdShipmentResponse.status, 201);
  const shipment = await createdShipmentResponse.json();
  assert.equal(shipment.tracking_code, "EU-2147");

  const duplicateShipment = await adminFetch("/api/admin/shipments", {
    method: "POST",
    body: JSON.stringify(shipmentInput),
  });
  assert.equal(duplicateShipment.status, 409);

  const invalidShipment = await adminFetch("/api/admin/shipments", {
    method: "POST",
    body: JSON.stringify({ ...shipmentInput, progress: 150 }),
  });
  assert.equal(invalidShipment.status, 400);

  const trackingResponse = await fetch(`${url}/api/track/eu-2147`);
  assert.equal(trackingResponse.status, 200);
  const initialTracking = await trackingResponse.json();
  assert.equal(initialTracking.status, "In transit");
  assert.ok(Number.isFinite(Date.parse(initialTracking.checkedAt)));
  assert.ok(Number.isFinite(Date.parse(initialTracking.updated_at)));
  assert.equal(initialTracking.trackingHistory.length, 1);
  assert.match(initialTracking.trackingHistory[0].description, /Shipment created/);
  assert.ok(Number.isFinite(Date.parse(initialTracking.trackingHistory[0].occurred_at)));

  const updatedShipment = await adminFetch(`/api/admin/shipments/${shipment.id}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "Delivered", progress: 100 }),
  });
  assert.equal(updatedShipment.status, 200);
  assert.equal((await updatedShipment.json()).status, "Delivered");
  const updatedTracking = await (await fetch(`${url}/api/track/EU-2147`)).json();
  assert.equal(updatedTracking.trackingHistory.length, 2);
  assert.match(updatedTracking.trackingHistory[0].description, /In transit to Delivered/);
  assert.equal(updatedTracking.trackingHistory[0].status, "Delivered");
  const unchangedShipment = await adminFetch(`/api/admin/shipments/${shipment.id}`, {
    method: "PATCH",
    body: JSON.stringify({ status: "Delivered", progress: 100 }),
  });
  assert.equal(unchangedShipment.status, 200);
  const afterUnchangedUpdate = await (await fetch(`${url}/api/track/EU-2147`)).json();
  assert.equal(afterUnchangedUpdate.trackingHistory.length, 2);
  const changedEta = await adminFetch(`/api/admin/shipments/${shipment.id}`, {
    method: "PATCH",
    body: JSON.stringify({ eta: "2026-10-25T12:30:00.000Z" }),
  });
  assert.equal(changedEta.status, 200);
  const afterEtaUpdate = await (await fetch(`${url}/api/track/EU-2147`)).json();
  assert.equal(afterEtaUpdate.trackingHistory.length, 3);
  assert.match(afterEtaUpdate.trackingHistory[0].description, /ETA updated/);

  const createdDriver = await adminFetch("/api/admin/drivers", {
    method: "POST",
    body: JSON.stringify({
      name: "Mila Dimas",
      region: "Athens",
      status: "Available",
      vehicle: "Euro 6 Truck",
      load_description: "3 pallets",
    }),
  });
  assert.equal(createdDriver.status, 201);

  const createdAllocation = await adminFetch("/api/admin/allocations", {
    method: "POST",
    body: JSON.stringify({
      region: "Greece",
      assigned: 42,
      utilization: 88,
      focus: "Ports and regional freight",
    }),
  });
  assert.equal(createdAllocation.status, 201);

  const dashboard = await (await fetch(`${url}/api/dashboard`)).json();
  assert.equal(dashboard.summary.totalShipments, 1);
  assert.equal(dashboard.summary.activeShipments, 0);
  assert.equal(dashboard.summary.driversOnline, 1);
  assert.equal(dashboard.allocations[0].region, "Greece");

  const events = await (await adminFetch("/api/admin/events")).json();
  assert.equal(events.length, 6);
  assert.equal(events[0].admin_email, ADMIN_EMAIL);

  const logout = await adminFetch("/api/admin/session", { method: "DELETE" });
  assert.equal(logout.status, 204);
  const expiredSession = await adminFetch("/api/admin/shipments");
  assert.equal(expiredSession.status, 401);
});
