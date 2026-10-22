# NorthStar Logistics

NorthStar is a standalone logistics website with an Express API, PostgreSQL
database, and password-protected operations admin portal. The project is
separate from the unrelated `fantasy-api` Render service.

The public GitHub Pages site remains a static demo. The database-backed
website and admin portal are served together by the Node.js app after it is
deployed.

## Local development

Requires Node.js 22+ and a PostgreSQL database.

1. Create a local PostgreSQL database named `northstar_logistics`.
2. Copy `.env.example` to `.env` and set `DATABASE_URL` and a bootstrap admin
   email/password.
3. Install dependencies and start the server:

```sh
npm ci
npm test
npm start
```

The website is at <http://localhost:3000>, the sign-in page at
<http://localhost:3000/admin>, and the database readiness endpoint at
<http://localhost:3000/health/ready>. The first startup applies the idempotent
schema and creates the initial admin account. No sample operational rows are
inserted.

## API

| Endpoint | Access | Purpose |
| --- | --- | --- |
| `GET /api/dashboard` | Public | Shipment/driver totals and regional allocation summary |
| `GET /api/track/:trackingCode` | Public, rate limited | Look up a shipment by tracking code |
| `POST /api/admin/session` | Public sign-in | Create an eight-hour, HTTP-only admin session |
| `GET /api/admin/session` | Admin | Check the current session |
| `DELETE /api/admin/session` | Admin | Sign out and revoke the session |
| `/api/admin/shipments` | Admin | List, create, edit, and delete shipment records |
| `/api/admin/drivers` | Admin | List, create, edit, and delete driver records |
| `/api/admin/allocations` | Admin | List, create, edit, and delete regional allocations |
| `GET /api/admin/events` | Admin | Review the latest 100 audited admin changes |
| `GET /health/live` | Public | Process liveness |
| `GET /health/ready` | Public | Database connectivity/readiness |

Admin passwords are hashed with Node's scrypt implementation. Session tokens
are random, stored only as hashes in PostgreSQL, and sent using HttpOnly,
SameSite=Strict cookies (Secure in production). Admin writes and their audit
events are committed in the same database transaction. Input fields and status
values are validated server-side.

Database tables and constraints are in [`src/schema.sql`](./src/schema.sql).
Set `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` only through a local
ignored `.env` file or the deployment platform's secret manager. The initial
bootstrap account is created once; changing those environment values later
does not reset its password.

## Deploy separately on Render

[`render.yaml`](./render.yaml) defines a dedicated NorthStar Node service and a
new PostgreSQL database; it does not reference or modify the `fantasy-api`
service. Deploy it as a Render Blueprint from this repository. Configure the
requested bootstrap admin credentials in Render's secret prompts.

The Blueprint uses paid Render web-service and PostgreSQL plans. Creating the
Blueprint in Render provisions billable infrastructure. No Render resources
have been created by this repository change; review current plan pricing and
confirm before applying it. GitHub Pages by itself cannot run this API or
connect to PostgreSQL.

## Demo limitations

The hosted GitHub Pages URL continues to use clearly labeled fictional sample
data until the Render app is deployed. The sample driver names, shipment
records, counts, and allocations are not live carrier information. The database
starts empty and becomes operational data only when an authorized admin adds
records.
