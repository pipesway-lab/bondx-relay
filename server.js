console.log("Starting BondX relay...");

const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * 🌍 Middleware
 */
app.use(
  cors({
    origin: "*",
  })
);

app.use(express.json());

/**
 * 🔐 Verificar si dos usuarios pertenecen al mismo vínculo
 */
async function areUsersLinked(userA, userB) {
  const result = await db.query(
    `
    SELECT lm1.link_id
    FROM link_members lm1
    JOIN link_members lm2 ON lm1.link_id = lm2.link_id
    WHERE lm1.user_public_key = $1
      AND lm2.user_public_key = $2
    LIMIT 1
    `,
    [userA, userB]
  );

  return result.rows.length > 0;
}

/**
 * 📩 Enviar mensaje
 */
app.post("/messages", async (req, res) => {
  console.log("📩 POST /messages recibido");
  console.log("Body:", req.body);

  const { toKey, fromKey, ciphertext, nonce, timestamp } = req.body;

  if (!toKey || !fromKey || !ciphertext || !nonce || !timestamp) {
    console.log("❌ Missing fields");
    return res.status(400).json({ error: "Missing fields" });
  }

  const id = uuidv4();

  try {
    // 🔐 Solo permitir mensajes entre usuarios vinculados
    const linked = await areUsersLinked(fromKey, toKey);

    if (!linked) {
      console.log("❌ Usuarios no vinculados. Mensaje rechazado.");
      return res.status(403).json({ error: "Users are not linked" });
    }

    await db.query(
      `
      INSERT INTO messages (id, tokey, fromkey, ciphertext, nonce, timestamp)
      VALUES ($1,$2,$3,$4,$5,$6)
      `,
      [id, toKey, fromKey, ciphertext, nonce, timestamp]
    );

    console.log("✅ Mensaje guardado con ID:", id);

    res.json({ success: true, id });
  } catch (err) {
    console.error("❌ DB INSERT ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 📥 Obtener mensajes pendientes
 */
app.get("/messages/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  console.log("📥 GET mensajes para:", publicKey);

  try {
    const result = await db.query(
      `
      SELECT *
      FROM messages
      WHERE tokey = $1 AND delivered = false
      ORDER BY timestamp ASC
      `,
      [publicKey]
    );

    console.log(`📦 ${result.rows.length} mensajes pendientes encontrados`);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ DB SELECT ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * ✅ Marcar mensaje como entregado
 */
app.post("/messages/:id/ack", async (req, res) => {
  const { id } = req.params;

  console.log("✅ ACK recibido para mensaje:", id);

  try {
    await db.query(
      `
      UPDATE messages
      SET delivered = true
      WHERE id = $1
      `,
      [id]
    );

    console.log("✔ Mensaje marcado como entregado:", id);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ DB UPDATE ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 👤 Registrar usuario si no existe
 */
async function ensureUser(publicKey) {
  await db.query(
    `
    INSERT INTO users (public_key)
    VALUES ($1)
    ON CONFLICT (public_key) DO NOTHING
    `,
    [publicKey]
  );
}

/**
 * 🔎 Obtener link activo de un usuario
 */
app.get("/links/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  try {
    const result = await db.query(
      `
      SELECT
        l.id,
        l.created_at,
        array_agg(lm.user_public_key) AS members
      FROM links l
      JOIN link_members lm ON lm.link_id = l.id
      WHERE l.id IN (
        SELECT lm2.link_id
        FROM link_members lm2
        WHERE lm2.user_public_key = $1
      )
      GROUP BY l.id, l.created_at
      ORDER BY l.created_at DESC
      LIMIT 1
      `,
      [publicKey]
    );

    if (result.rows.length === 0) {
      return res.json(null);
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ GET /links error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 📩 Crear solicitud de vínculo
 */
app.post("/link-request", async (req, res) => {
  const { fromUser, toUser } = req.body;

  if (!fromUser || !toUser || fromUser === toUser) {
    return res.status(400).json({ error: "Invalid users" });
  }

  try {
    await ensureUser(fromUser);
    await ensureUser(toUser);

    // evitar duplicados pendientes
    const existingPending = await db.query(
      `
      SELECT id
      FROM link_requests
      WHERE from_user = $1
        AND to_user = $2
        AND status = 'pending'
      LIMIT 1
      `,
      [fromUser, toUser]
    );

    if (existingPending.rows.length > 0) {
      return res.json({
        success: true,
        requestId: existingPending.rows[0].id,
        alreadyPending: true,
      });
    }

    const result = await db.query(
      `
      INSERT INTO link_requests (from_user, to_user, status)
      VALUES ($1, $2, 'pending')
      RETURNING id
      `,
      [fromUser, toUser]
    );

    res.json({
      success: true,
      requestId: result.rows[0].id,
    });
  } catch (err) {
    console.error("❌ POST /link-request error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 📥 Ver solicitudes pendientes recibidas
 */
app.get("/link-requests/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  try {
    const result = await db.query(
      `
      SELECT id, from_user, to_user, status, created_at
      FROM link_requests
      WHERE to_user = $1
        AND status = 'pending'
      ORDER BY created_at ASC
      `,
      [publicKey]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /link-requests error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * ✅ Aceptar solicitud de vínculo
 */
app.post("/link-accept", async (req, res) => {
  const { requestId } = req.body;

  if (!requestId) {
    return res.status(400).json({ error: "Missing requestId" });
  }

  try {
    const requestResult = await db.query(
      `
      SELECT *
      FROM link_requests
      WHERE id = $1
        AND status = 'pending'
      LIMIT 1
      `,
      [requestId]
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: "Request not found" });
    }

    const request = requestResult.rows[0];

    const linkResult = await db.query(
      `
      INSERT INTO links DEFAULT VALUES
      RETURNING id
      `
    );

    const linkId = linkResult.rows[0].id;

    await db.query(
      `
      INSERT INTO link_members (link_id, user_public_key)
      VALUES ($1, $2), ($1, $3)
      `,
      [linkId, request.from_user, request.to_user]
    );

    await db.query(
      `
      UPDATE link_requests
      SET status = 'accepted'
      WHERE id = $1
      `,
      [requestId]
    );

    res.json({
      success: true,
      linkId,
    });
  } catch (err) {
    console.error("❌ POST /link-accept error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 💔 Desvincular link
 */
app.post("/links/:id/unlink", async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      `
      DELETE FROM link_members
      WHERE link_id = $1
      `,
      [id]
    );

    await db.query(
      `
      DELETE FROM links
      WHERE id = $1
      `,
      [id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ POST /links/:id/unlink error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🩺 Health check
 */
app.get("/health", (req, res) => {
  console.log("🩺 Health check solicitado");
  res.json({ status: "ok" });
});

/**
 * 🚀 Iniciar servidor
 */
app.listen(PORT, "0.0.0.0", () => {
  console.log("=================================");
  console.log("BondX relay running");
  console.log(`Local:   http://localhost:${PORT}/health`);
  console.log("=================================");
});
