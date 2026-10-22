import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const schemaPath = fileURLToPath(new URL("./schema.sql", import.meta.url));

export async function migrate(pool) {
  const schema = await readFile(schemaPath, "utf8");
  const statements = schema.split(";").map((statement) => statement.trim()).filter(Boolean);
  for (const statement of statements) {
    await pool.query(statement);
  }
}
