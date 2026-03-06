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