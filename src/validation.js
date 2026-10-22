const shipmentModes = new Set(["Road freight", "Air priority", "Regional LTL", "Sea freight", "Express"]);
const shipmentStatuses = new Set(["Booked", "Loading", "In transit", "Customs", "Cleared", "Delivered", "Delayed"]);
const driverStatuses = new Set(["Available", "On route", "Break", "Off duty"]);

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
    this.status = 400;
  }
}

function requireText(value, label, maxLength = 160) {
  if (typeof value !== "string" || !value.trim() || value.trim().length > maxLength) {
    throw new ValidationError(`${label} must be a non-empty string of at most ${maxLength} characters.`);
  }
  return value.trim();
}

function requireChoice(value, choices, label) {
  if (!choices.has(value)) {
    throw new ValidationError(`${label} is not a supported value.`);
  }
  return value;
}

function requireInteger(value, label, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ValidationError(`${label} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function rejectUnknownKeys(body, fields) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ValidationError("Request body must be a JSON object.");
  }
  const unknown = Object.keys(body).filter((key) => !fields.includes(key));
  if (unknown.length) throw new ValidationError(`Unsupported field: ${unknown[0]}.`);
}

export function validateShipment(body) {
  const fields = ["tracking_code", "origin", "destination", "mode", "status", "eta", "progress"];
  rejectUnknownKeys(body, fields);
  if (!/^[A-Z0-9][A-Z0-9-]{2,31}$/.test(body.tracking_code ?? "")) {
    throw new ValidationError("tracking_code must be 3–32 uppercase letters, digits, or hyphens.");
  }
  const eta = new Date(body.eta);
  if (!(typeof body.eta === "string" || body.eta instanceof Date) || !Number.isFinite(eta.getTime())) {
    throw new ValidationError("eta must be a valid date-time string.");
  }
  return {
    tracking_code: body.tracking_code,
    origin: requireText(body.origin, "origin"),
    destination: requireText(body.destination, "destination"),
    mode: requireChoice(body.mode, shipmentModes, "mode"),
    status: requireChoice(body.status, shipmentStatuses, "status"),
    eta: eta.toISOString(),
    progress: requireInteger(body.progress, "progress", 0, 100),
  };
}

export function validateDriver(body) {
  const fields = ["name", "region", "status", "vehicle", "load_description"];
  rejectUnknownKeys(body, fields);
  return {
    name: requireText(body.name, "name", 100),
    region: requireText(body.region, "region", 100),
    status: requireChoice(body.status, driverStatuses, "status"),
    vehicle: requireText(body.vehicle, "vehicle", 120),
    load_description: requireText(body.load_description, "load_description", 200),
  };
}

export function validateAllocation(body) {
  const fields = ["region", "assigned", "utilization", "focus"];
  rejectUnknownKeys(body, fields);
  return {
    region: requireText(body.region, "region", 100),
    assigned: requireInteger(body.assigned, "assigned", 0, 1_000_000),
    utilization: requireInteger(body.utilization, "utilization", 0, 100),
    focus: requireText(body.focus, "focus", 240),
  };
}
