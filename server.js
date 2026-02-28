console.log("Starting BondX relay...");

const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const db = require("./db");

const app = express();
const PORT = 3000;

/**
 * 🌍 Middleware
 */
app.use(
  cors({
    origin: "*", // desarrollo LAN
  })
);

app.use(express.json());

/**
 * 📩 Enviar mensaje
 */
app.post("/messages", (req, res) => {
  console.log("📩 POST /messages recibido");
  console.log("Body:", req.body);

  const { toKey, fromKey, ciphertext, nonce, timestamp } = req.body;

  if (!toKey || !fromKey || !ciphertext || !nonce || !timestamp) {
    console.log("❌ Missing fields");
    return res.status(400).json({ error: "Missing fields" });
  }

  const id = uuidv4();

  db.run(
    `
    INSERT INTO messages (id, toKey, fromKey, ciphertext, nonce, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    `,
    [id, toKey, fromKey, ciphertext, nonce, timestamp],
    function (err) {
      if (err) {
        console.error("❌ DB INSERT ERROR:", err);
        return res.status(500).json({ error: "DB error" });
      }

      console.log("✅ Mensaje guardado con ID:", id);

      res.json({ success: true, id });
    }
  );
});

/**
 * 📥 Obtener mensajes pendientes
 */
app.get("/messages/:publicKey", (req, res) => {
  const { publicKey } = req.params;

  console.log("📥 GET mensajes para:", publicKey);

  db.all(
    `
    SELECT * FROM messages
    WHERE toKey = ? AND delivered = 0
    ORDER BY timestamp ASC
    `,
    [publicKey],
    (err, rows) => {
      if (err) {
        console.error("❌ DB SELECT ERROR:", err);
        return res.status(500).json({ error: "DB error" });
      }

      console.log(`📦 ${rows.length} mensajes pendientes encontrados`);

      res.json(rows);
    }
  );
});

/**
 * ✅ Marcar mensaje como entregado
 */
app.post("/messages/:id/ack", (req, res) => {
  const { id } = req.params;

  console.log("✅ ACK recibido para mensaje:", id);

  db.run(
    `
    UPDATE messages
    SET delivered = 1
    WHERE id = ?
    `,
    [id],
    function (err) {
      if (err) {
        console.error("❌ DB UPDATE ERROR:", err);
        return res.status(500).json({ error: "DB error" });
      }

      console.log("✔ Mensaje marcado como entregado:", id);

      res.json({ success: true });
    }
  );
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
  console.log(`LAN:     http://TU_IP_LOCAL:${PORT}/health`);
  console.log("=================================");
});
