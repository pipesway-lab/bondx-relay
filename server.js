console.log("Starting BondX relay...");

const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const nacl = require("tweetnacl");
const { decodeBase64 } = require("tweetnacl-util");
const OpenAI = require("openai");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutos

const AI_PROVIDER = process.env.AI_PROVIDER || "openai";
const SUMMARY_MODEL = process.env.OPENAI_SUMMARY_MODEL || "gpt-5.4";

const openai =
  process.env.OPENAI_API_KEY && AI_PROVIDER === "openai"
    ? new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
      })
    : null;

/**
 * 🌍 Middleware
 */
app.use(
  cors({
    origin: "*",
  }),
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
    [userA, userB],
  );

  return result.rows.length > 0;
}

/**
 * 🔗 Obtener el link_id compartido entre dos usuarios
 */
async function getSharedLinkId(userA, userB) {
  const result = await db.query(
    `
    SELECT lm1.link_id
    FROM link_members lm1
    JOIN link_members lm2 ON lm1.link_id = lm2.link_id
    WHERE lm1.user_public_key = $1
      AND lm2.user_public_key = $2
    LIMIT 1
    `,
    [userA, userB],
  );

  return result.rows.length > 0 ? result.rows[0].link_id : null;
}

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
    [publicKey],
  );
}

/**
 * 🔑 Vincular o verificar signing public key de un usuario
 *
 * Modelo TOFU (trust on first use):
 * la primera vez que el servidor ve un signerPublicKey para un publicKey,
 * lo almacena. Después debe coincidir siempre.
 */
async function bindOrVerifySigningKey(userPublicKey, signerPublicKey) {
  const existing = await db.query(
    `
    SELECT signing_public_key
    FROM users
    WHERE public_key = $1
    LIMIT 1
    `,
    [userPublicKey],
  );

  if (existing.rows.length === 0) {
    await db.query(
      `
      INSERT INTO users (public_key, signing_public_key)
      VALUES ($1, $2)
      `,
      [userPublicKey, signerPublicKey],
    );
    return true;
  }

  const stored = existing.rows[0].signing_public_key;

  if (!stored) {
    await db.query(
      `
      UPDATE users
      SET signing_public_key = $2
      WHERE public_key = $1
      `,
      [userPublicKey, signerPublicKey],
    );
    return true;
  }

  return stored === signerPublicKey;
}

/**
 * 🔍 Buscar usuario por signing public key
 */
async function getUserBySigningPublicKey(signerPublicKey) {
  const result = await db.query(
    `
    SELECT public_key
    FROM users
    WHERE signing_public_key = $1
    LIMIT 1
    `,
    [signerPublicKey],
  );

  return result.rows.length > 0 ? result.rows[0].public_key : null;
}

/**
 * ✅ Verifica firma detached Ed25519
 */
function verifySignature(
  canonicalPayload,
  signatureBase64,
  signerPublicKeyBase64,
) {
  try {
    const messageBytes = Buffer.from(canonicalPayload, "utf8");
    const signature = decodeBase64(signatureBase64);
    const signerPublicKey = decodeBase64(signerPublicKeyBase64);

    return nacl.sign.detached.verify(messageBytes, signature, signerPublicKey);
  } catch (err) {
    console.error("❌ Signature verification error:", err);
    return false;
  }
}

/**
 * 🧾 Verifica request firmado
 */
function verifySignedRequest(payloadFields, reqBody) {
  const { signedAt, signerPublicKey, signature } = reqBody;

  if (!signedAt || !signerPublicKey || !signature) {
    return {
      ok: false,
      status: 400,
      error: "Missing signature fields",
    };
  }

  const age = Math.abs(Date.now() - Number(signedAt));
  if (Number.isNaN(age) || age > SIGNATURE_MAX_AGE_MS) {
    return {
      ok: false,
      status: 401,
      error: "Signature expired or invalid timestamp",
    };
  }

  const canonicalPayload = JSON.stringify({
    ...payloadFields,
    signedAt,
    signerPublicKey,
  });

  const valid = verifySignature(canonicalPayload, signature, signerPublicKey);

  if (!valid) {
    return {
      ok: false,
      status: 401,
      error: "Invalid signature",
    };
  }

  return {
    ok: true,
    signerPublicKey,
    signedAt,
  };
}

/**
 * 🤖 Extrae JSON de una respuesta de texto
 */
function extractJsonObject(text) {
  if (!text) {
    throw new Error("Empty model response");
  }

  try {
    return JSON.parse(text);
  } catch {
    const firstBrace = text.indexOf("{");
    const lastBrace = text.lastIndexOf("}");

    if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
      throw new Error("No JSON object found in model response");
    }

    const maybeJson = text.slice(firstBrace, lastBrace + 1);
    return JSON.parse(maybeJson);
  }
}

/**
 * 🤖 Generar resumen IA de un awareness
 */
async function generateAwarenessSummary(context) {
  if (!openai) {
    throw new Error("OpenAI not configured");
  }

  const systemPrompt = `
Eres un facilitador experto en comunicación de pareja.

Tu tarea es sintetizar la evolución de un tema sensible de forma:
clara, equilibrada y útil para el cuidado mutuo y contextualizar toda la información y enmarcarla dentro de una historia del ecosistema emocional de la relación..

Principios:
- redactar el contenido en una voz cercana y compartida pero ante todo muy natural, usa un lenguaje coloquial que no suene a evaluación
- preferir primera persona del plural cuando sea natural ("nos", "estamos", "puede ayudarnos")
- evitar tono de informe externo o análisis en tercera persona
- mantener prudencia: no asumir acuerdos o mejoras que no estén respaldados por la información
- tono empático, humano y respetuoso
- no tomar partido
- no culpar ni juzgar
- no diagnosticar ni usar lenguaje clínico
- evitar frases genéricas de autoayuda
- no sonar excesivamente terapéutico
- basarte solo en la información proporcionada
- detectar si hay señales de mejora, estancamiento, tensión o ambivalencia
- reconocer avances aunque sean pequeños
- identificar posibles diferencias de percepción entre ambas personas
- proponer un foco de atención pequeño, concreto y realista

El insight debe ayudar a la pareja a:
comprender mejor lo que está ocurriendo y ajustar algo de forma práctica.

Devuelve SOLO JSON válido con esta forma exacta:

{
  "trend": "improving" | "stable" | "worsening" | "mixed",
  "summary": "síntesis breve de lo que parece estar ocurriendo",
  "what_helps": "qué parece contribuir a que la situación mejore o se estabilice",
  "open_tension": "qué aspecto sigue generando fricción o incertidumbre",
  "suggested_focus": "una sugerencia pequeña y concreta de atención o ajuste"
}
`.trim();

  const userPrompt = `
Resume este awareness relacional usando únicamente la información proporcionada.

${JSON.stringify(context, null, 2)}
`.trim();

  const response = await openai.responses.create({
    model: SUMMARY_MODEL,
    input: [
      {
        role: "system",
        content: systemPrompt,
      },
      {
        role: "user",
        content: userPrompt,
      },
    ],
  });

  const parsed = extractJsonObject(response.output_text);

  const allowedTrends = ["improving", "stable", "worsening", "mixed"];

  if (!allowedTrends.includes(parsed.trend)) {
    throw new Error("Invalid trend returned by model");
  }

  const requiredFields = [
    "trend",
    "summary",
    "what_helps",
    "open_tension",
    "suggested_focus",
  ];

  for (const field of requiredFields) {
    if (
      typeof parsed[field] !== "string" &&
      !(field === "trend" && typeof parsed[field] === "string")
    ) {
      throw new Error(`Invalid or missing field: ${field}`);
    }
  }

  return parsed;
}

/**
 * 🤖 Construir contexto para resumen de awareness
 */
async function buildAwarenessSummaryContext(awarenessId) {
  const awarenessResult = await db.query(
    `
    SELECT
      ai.*,
      COALESCE(
        json_agg(aa.user_public_key)
        FILTER (WHERE aa.user_public_key IS NOT NULL),
        '[]'
      ) AS acknowledged_by,
      MAX(aa.created_at) AS last_acknowledged_at
    FROM awareness_items ai
    LEFT JOIN awareness_acknowledgements aa
      ON ai.id = aa.awareness_item_id
    WHERE ai.id = $1
    GROUP BY ai.id
    LIMIT 1
    `,
    [awarenessId],
  );

  if (awarenessResult.rows.length === 0) {
    throw new Error("Awareness item not found");
  }

  const awareness = awarenessResult.rows[0];

  const checkinsResult = await db.query(
    `
    SELECT *
    FROM awareness_checkins
    WHERE awareness_item_id = $1
    ORDER BY created_at ASC
    `,
    [awarenessId],
  );

  const checkins = checkinsResult.rows;

  const closedCheckins = checkins.filter((checkin) => checkin.status === "closed");

  if (closedCheckins.length === 0) {
    throw new Error("No closed check-ins available for summary");
  }

  const history = [];

  for (const checkin of closedCheckins) {
    const responsesResult = await db.query(
      `
      SELECT *
      FROM awareness_checkin_responses
      WHERE checkin_id = $1
      ORDER BY created_at ASC
      `,
      [checkin.id],
    );

    const responses = responsesResult.rows.map((response) => ({
      role:
        response.user_public_key === awareness.created_by_user_key
          ? "creator"
          : "partner",
      user_public_key: response.user_public_key,
      text: response.response_text,
      created_at: response.created_at,
    }));

    history.push({
      checkin_id: checkin.id,
      date: checkin.created_at,
      question: checkin.question,
      responses,
    });
  }

  return {
    awareness: {
      id: awareness.id,
      title: awareness.title,
      impact_description: awareness.impact_description,
      support_needed: awareness.support_needed,
      created_at: awareness.created_at,
      updated_at: awareness.updated_at,
      created_by_user_key: awareness.created_by_user_key,
    },
    acknowledged_by: awareness.acknowledged_by || [],
    last_acknowledged_at: awareness.last_acknowledged_at,
    checkins: history,
    latest_closed_checkin_id: closedCheckins[closedCheckins.length - 1].id,
  };
}

/**
 * 📩 Enviar mensaje
 */
app.post("/messages", async (req, res) => {
  console.log("📩 POST /messages recibido");
  console.log("Body:", req.body);

  const {
    toKey,
    fromKey,
    ciphertext,
    nonce,
    timestamp,
    category = "general",
    signedAt,
    signerPublicKey,
    signature,
  } = req.body;

  if (!toKey || !fromKey || !ciphertext || !nonce || !timestamp) {
    console.log("❌ Missing fields");
    return res.status(400).json({ error: "Missing fields" });
  }

  if (!["general", "fuego"].includes(category)) {
    console.log("❌ Invalid category");
    return res.status(400).json({ error: "Invalid category" });
  }

  const signatureCheck = verifySignedRequest(
    { toKey, fromKey, ciphertext, nonce, timestamp, category },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    const signingKeyOk = await bindOrVerifySigningKey(fromKey, signerPublicKey);
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match sender" });
    }

    const linked = await areUsersLinked(fromKey, toKey);

    if (!linked) {
      console.log("❌ Usuarios no vinculados. Mensaje rechazado.");
      return res.status(403).json({ error: "Users are not linked" });
    }

    const id = uuidv4();

    await db.query(
      `
      INSERT INTO messages (id, tokey, fromkey, ciphertext, nonce, timestamp, category)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      `,
      [id, toKey, fromKey, ciphertext, nonce, timestamp, category],
    );

    console.log("✅ Mensaje guardado con ID:", id);

    res.json({ success: true, id });
  } catch (err) {
    console.error("❌ DB INSERT ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 📤 Obtener estado de mensajes enviados
 * Devuelve también read_at para soportar "leído"
 *
 * ⚠️ Va antes que /messages/:publicKey para evitar colisión de rutas
 */
app.get("/messages/sent/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  try {
    const result = await db.query(
      `
      SELECT id, delivered, read_at
      FROM messages
      WHERE fromkey = $1
      ORDER BY timestamp DESC
      LIMIT 50
      `,
      [publicKey],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /messages/sent error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 📥 Obtener mensajes pendientes
 * Solo devuelve mensajes cuyo emisor y receptor sigan vinculados.
 */
app.get("/messages/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  console.log("📥 GET mensajes para:", publicKey);

  try {
    const result = await db.query(
      `
      SELECT m.*
      FROM messages m
      WHERE m.tokey = $1
        AND m.delivered = false
        AND EXISTS (
          SELECT 1
          FROM link_members lm1
          JOIN link_members lm2 ON lm1.link_id = lm2.link_id
          WHERE lm1.user_public_key = m.fromkey
            AND lm2.user_public_key = m.tokey
        )
      ORDER BY m.timestamp ASC
      `,
      [publicKey],
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
 * Solo hace ACK si el mensaje pertenece a usuarios que siguen vinculados.
 */
app.post("/messages/:id/ack", async (req, res) => {
  const { id } = req.params;
  const { signedAt, signerPublicKey, signature } = req.body;

  console.log("✅ ACK recibido para mensaje:", id);

  const signatureCheck = verifySignedRequest(
    { id },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    const messageResult = await db.query(
      `
      SELECT id, fromkey, tokey
      FROM messages
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    const message = messageResult.rows[0];

    const signingKeyOk = await bindOrVerifySigningKey(
      message.tokey,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match recipient" });
    }

    const linked = await areUsersLinked(message.fromkey, message.tokey);

    if (!linked) {
      console.log("❌ ACK rechazado: usuarios ya no vinculados.");
      return res.status(403).json({ error: "Users are not linked" });
    }

    await db.query(
      `
      UPDATE messages
      SET delivered = true
      WHERE id = $1
      `,
      [id],
    );

    console.log("✔ Mensaje marcado como entregado:", id);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ DB UPDATE ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 👁️ Marcar mensaje como leído
 * Solo permite marcar como leído si el mensaje existe y ambos usuarios siguen vinculados.
 */
app.post("/messages/:id/read", async (req, res) => {
  const { id } = req.params;
  const { signedAt, signerPublicKey, signature } = req.body;

  console.log("👁️ READ recibido para mensaje:", id);

  const signatureCheck = verifySignedRequest(
    { id },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    const messageResult = await db.query(
      `
      SELECT id, fromkey, tokey, read_at
      FROM messages
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (messageResult.rows.length === 0) {
      return res.status(404).json({ error: "Message not found" });
    }

    const message = messageResult.rows[0];

    const signingKeyOk = await bindOrVerifySigningKey(
      message.tokey,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match recipient" });
    }

    const linked = await areUsersLinked(message.fromkey, message.tokey);

    if (!linked) {
      console.log("❌ READ rechazado: usuarios ya no vinculados.");
      return res.status(403).json({ error: "Users are not linked" });
    }

    await db.query(
      `
      UPDATE messages
      SET read_at = NOW()
      WHERE id = $1
      `,
      [id],
    );

    console.log("✔ Mensaje marcado como leído:", id);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ DB READ UPDATE ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

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
      [publicKey],
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
  const { fromUser, toUser, signedAt, signerPublicKey, signature } = req.body;

  if (!fromUser || !toUser || fromUser === toUser) {
    return res.status(400).json({ error: "Invalid users" });
  }

  const signatureCheck = verifySignedRequest(
    { fromUser, toUser },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    await ensureUser(fromUser);
    await ensureUser(toUser);

    const signingKeyOk = await bindOrVerifySigningKey(
      fromUser,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match fromUser" });
    }

    const existingPending = await db.query(
      `
      SELECT id
      FROM link_requests
      WHERE from_user = $1
        AND to_user = $2
        AND status = 'pending'
      LIMIT 1
      `,
      [fromUser, toUser],
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
      [fromUser, toUser],
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
      [publicKey],
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
  const { requestId, signedAt, signerPublicKey, signature } = req.body;

  if (!requestId) {
    return res.status(400).json({ error: "Missing requestId" });
  }

  const signatureCheck = verifySignedRequest(
    { requestId },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
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
      [requestId],
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: "Request not found" });
    }

    const request = requestResult.rows[0];

    const signingKeyOk = await bindOrVerifySigningKey(
      request.to_user,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match receiver" });
    }

    const linkResult = await db.query(
      `
      INSERT INTO links DEFAULT VALUES
      RETURNING id
      `,
    );

    const linkId = linkResult.rows[0].id;

    await db.query(
      `
      INSERT INTO link_members (link_id, user_public_key)
      VALUES ($1, $2), ($1, $3)
      `,
      [linkId, request.from_user, request.to_user],
    );

    await db.query(
      `
      UPDATE link_requests
      SET status = 'accepted'
      WHERE id = $1
      `,
      [requestId],
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
  const { linkId, signedAt, signerPublicKey, signature } = req.body;

  if (!linkId || String(linkId) !== String(id)) {
    return res.status(400).json({ error: "Invalid linkId" });
  }

  const signatureCheck = verifySignedRequest(
    { linkId },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    const signerUser = await getUserBySigningPublicKey(signerPublicKey);

    if (!signerUser) {
      return res.status(403).json({ error: "Unknown signer" });
    }

    const membership = await db.query(
      `
      SELECT 1
      FROM link_members
      WHERE link_id = $1
        AND user_public_key = $2
      LIMIT 1
      `,
      [id, signerUser],
    );

    if (membership.rows.length === 0) {
      return res
        .status(403)
        .json({ error: "Signer is not a member of this link" });
    }

    await db.query(
      `
      DELETE FROM link_members
      WHERE link_id = $1
      `,
      [id],
    );

    await db.query(
      `
      DELETE FROM links
      WHERE id = $1
      `,
      [id],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ POST /links/:id/unlink error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 👤 Obtener perfil básico de un usuario
 * Si no existe todavía, lo crea automáticamente con valores por defecto.
 */
app.get("/users/:publicKey", async (req, res) => {
  const { publicKey } = req.params;

  try {
    await ensureUser(publicKey);

    const result = await db.query(
      `
      SELECT public_key, relationship_preference
      FROM users
      WHERE public_key = $1
      LIMIT 1
      `,
      [publicKey],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ GET /users/:publicKey error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🔔 Registrar token push de usuario
 * Requiere firma
 */
app.post("/users/push-token", async (req, res) => {
  const {
    publicKey,
    pushToken,
    platform,
    signedAt,
    signerPublicKey,
    signature,
  } = req.body;

  if (!publicKey || !pushToken || !platform) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const signatureCheck = verifySignedRequest(
    { publicKey, pushToken, platform },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    await ensureUser(publicKey);

    const signingKeyOk = await bindOrVerifySigningKey(
      publicKey,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match user" });
    }

    const result = await db.query(
      `
      INSERT INTO push_tokens (user_public_key, push_token, platform, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (push_token)
      DO UPDATE SET
        user_public_key = EXCLUDED.user_public_key,
        platform = EXCLUDED.platform,
        updated_at = NOW()
      RETURNING id, user_public_key, push_token, platform, created_at, updated_at
      `,
      [publicKey, pushToken, platform],
    );

    res.json({
      success: true,
      pushToken: result.rows[0],
    });
  } catch (err) {
    console.error("❌ POST /users/push-token error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * ❤️ Actualizar preferencia relacional del usuario
 * Requiere firma
 */
app.post("/users/preference", async (req, res) => {
  const {
    publicKey,
    preference,
    signedAt,
    signerPublicKey,
    signature,
  } = req.body;

  if (!publicKey || !preference) {
    return res.status(400).json({ error: "Missing fields" });
  }

  if (!["closed", "open"].includes(preference)) {
    return res.status(400).json({ error: "Invalid preference" });
  }

  const signatureCheck = verifySignedRequest(
    { publicKey, preference },
    { signedAt, signerPublicKey, signature },
  );

  if (!signatureCheck.ok) {
    return res
      .status(signatureCheck.status)
      .json({ error: signatureCheck.error });
  }

  try {
    await ensureUser(publicKey);

    const signingKeyOk = await bindOrVerifySigningKey(
      publicKey,
      signerPublicKey,
    );
    if (!signingKeyOk) {
      return res.status(403).json({ error: "Signer does not match user" });
    }

    await db.query(
      `
      UPDATE users
      SET relationship_preference = $2
      WHERE public_key = $1
      `,
      [publicKey, preference],
    );

    res.json({ success: true, preference });
  } catch (err) {
    console.error("❌ POST /users/preference error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Obtener awareness items de un vínculo
 */
app.get("/awareness/:linkId", async (req, res) => {
  const linkId = parseInt(req.params.linkId, 10);

  if (Number.isNaN(linkId)) {
    return res.status(400).json({ error: "Invalid linkId" });
  }

  try {
    const result = await db.query(
      `
      SELECT
        ai.*,

        COALESCE(
          json_agg(aa.user_public_key)
          FILTER (WHERE aa.user_public_key IS NOT NULL),
          '[]'
        ) AS acknowledged_by,

        MAX(aa.created_at) AS last_acknowledged_at

      FROM awareness_items ai

      LEFT JOIN awareness_acknowledgements aa
        ON ai.id = aa.awareness_item_id

      WHERE ai.link_id = $1
        AND ai.archived = false

      GROUP BY ai.id

      ORDER BY ai.created_at DESC
      `,
      [linkId],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching awareness:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Obtener resúmenes IA de un awareness
 */
app.get("/awareness/:id/summaries", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `
      SELECT *
      FROM awareness_summaries
      WHERE awareness_item_id = $1
      ORDER BY created_at DESC
      `,
      [id],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /awareness/:id/summaries error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Generar resumen IA de un awareness
 */
app.post("/awareness/:id/summary", async (req, res) => {
  const { id } = req.params;

  try {
    const context = await buildAwarenessSummaryContext(id);
    const summary = await generateAwarenessSummary(context);

    const insertResult = await db.query(
      `
      INSERT INTO awareness_summaries
      (
        awareness_item_id,
        trend,
        summary,
        what_helps,
        open_tension,
        suggested_focus,
        source_checkin_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
      `,
      [
        id,
        summary.trend,
        summary.summary,
        summary.what_helps,
        summary.open_tension,
        summary.suggested_focus,
        context.latest_closed_checkin_id,
      ],
    );

    res.json(insertResult.rows[0]);
  } catch (err) {
    console.error("❌ POST /awareness/:id/summary error:", err);

    if (err.message === "Awareness item not found") {
      return res.status(404).json({ error: err.message });
    }

    if (err.message === "No closed check-ins available for summary") {
      return res.status(400).json({ error: err.message });
    }

    if (err.message === "OpenAI not configured") {
      return res.status(500).json({ error: "AI provider not configured" });
    }

    res.status(500).json({ error: "DB or AI error" });
  }
});

/**
 * 🌿 Crear awareness item
 */
app.post("/awareness", async (req, res) => {
  const {
    linkId,
    createdByUserKey,
    title,
    impactDescription,
    supportNeeded,
  } = req.body;

  if (
    !linkId ||
    !createdByUserKey ||
    !title ||
    !impactDescription ||
    !supportNeeded
  ) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const result = await db.query(
      `
      INSERT INTO awareness_items
      (link_id, created_by_user_key, title, impact_description, support_needed)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [linkId, createdByUserKey, title, impactDescription, supportNeeded],
    );

    res.json({
      ...result.rows[0],
      acknowledged_by: [],
      last_acknowledged_at: null,
    });
  } catch (err) {
    console.error("❌ Error creating awareness item:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Editar awareness item
 */
app.patch("/awareness/:id", async (req, res) => {
  const { id } = req.params;
  const {
    userPublicKey,
    title,
    impactDescription,
    supportNeeded,
  } = req.body;

  if (!userPublicKey || !title || !impactDescription || !supportNeeded) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const existing = await db.query(
      `
      SELECT created_by_user_key
      FROM awareness_items
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    const item = existing.rows[0];

    if (item.created_by_user_key !== userPublicKey) {
      return res.status(403).json({ error: "Not allowed" });
    }

    const result = await db.query(
      `
      UPDATE awareness_items
      SET
        title = $2,
        impact_description = $3,
        support_needed = $4,
        updated_at = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [id, title, impactDescription, supportNeeded],
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ PATCH /awareness/:id error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Marcar awareness item como tenido en cuenta
 */
app.post("/awareness/:id/ack", async (req, res) => {
  const { id } = req.params;
  const { userPublicKey } = req.body;

  if (!id || !userPublicKey) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const itemResult = await db.query(
      `
      SELECT *
      FROM awareness_items
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (itemResult.rows.length === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    const item = itemResult.rows[0];

    const membership = await db.query(
      `
      SELECT 1
      FROM link_members
      WHERE link_id = $1
        AND user_public_key = $2
      LIMIT 1
      `,
      [item.link_id, userPublicKey],
    );

    if (membership.rows.length === 0) {
      return res.status(403).json({ error: "Not part of this link" });
    }

    await db.query(
      `
      INSERT INTO awareness_acknowledgements (awareness_item_id, user_public_key)
      VALUES ($1, $2)
      ON CONFLICT (awareness_item_id, user_public_key) DO NOTHING
      `,
      [id, userPublicKey],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ ACK awareness error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 💬 Crear check-in para un awareness item
 */
app.post("/awareness/:id/checkins", async (req, res) => {
  const { id } = req.params;

  try {
    const awarenessResult = await db.query(
      `
      SELECT id, archived
      FROM awareness_items
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (awarenessResult.rows.length === 0) {
      return res.status(404).json({ error: "Awareness item not found" });
    }

    const awarenessItem = awarenessResult.rows[0];

    if (awarenessItem.archived) {
      return res.status(400).json({ error: "Awareness item is archived" });
    }

    const activeCheckinResult = await db.query(
      `
      SELECT id
      FROM awareness_checkins
      WHERE awareness_item_id = $1
        AND status = 'active'
      LIMIT 1
      `,
      [id],
    );

    if (activeCheckinResult.rows.length > 0) {
      return res.json({
        success: true,
        alreadyExists: true,
        checkin: activeCheckinResult.rows[0],
      });
    }

    const result = await db.query(
      `
      INSERT INTO awareness_checkins (awareness_item_id, question, status)
      VALUES ($1, $2, 'active')
      RETURNING *
      `,
      [id, "¿Cómo está evolucionando esto últimamente?"],
    );

    res.json({
      success: true,
      checkin: result.rows[0],
    });
  } catch (err) {
    console.error("❌ POST /awareness/:id/checkins error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 💬 Obtener check-ins de un awareness item
 */
app.get("/awareness/:id/checkins", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `
      SELECT *
      FROM awareness_checkins
      WHERE awareness_item_id = $1
      ORDER BY created_at DESC
      `,
      [id],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /awareness/:id/checkins error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 💬 Responder a un check-in
 */
app.post("/checkins/:id/respond", async (req, res) => {
  const { id } = req.params;
  const { userPublicKey, responseText } = req.body;

  if (!userPublicKey || !responseText) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const checkinResult = await db.query(
      `
      SELECT *
      FROM awareness_checkins
      WHERE id = $1
      LIMIT 1
      `,
      [id],
    );

    if (checkinResult.rows.length === 0) {
      return res.status(404).json({ error: "Check-in not found" });
    }

    const checkin = checkinResult.rows[0];

    if (checkin.status !== "active") {
      return res.status(400).json({ error: "Check-in is not active" });
    }

    const insertResult = await db.query(
      `
      INSERT INTO awareness_checkin_responses (checkin_id, user_public_key, response_text)
      VALUES ($1, $2, $3)
      ON CONFLICT (checkin_id, user_public_key)
      DO UPDATE SET response_text = EXCLUDED.response_text
      RETURNING *
      `,
      [id, userPublicKey, responseText],
    );

    const responsesCountResult = await db.query(
      `
      SELECT COUNT(*)::int AS count
      FROM awareness_checkin_responses
      WHERE checkin_id = $1
      `,
      [id],
    );

    const responsesCount = responsesCountResult.rows[0].count;

    if (responsesCount >= 2) {
      await db.query(
        `
        UPDATE awareness_checkins
        SET status = 'closed',
            closed_at = NOW()
        WHERE id = $1
        `,
        [id],
      );
    }

    res.json({
      success: true,
      response: insertResult.rows[0],
      closed: responsesCount >= 2,
    });
  } catch (err) {
    console.error("❌ POST /checkins/:id/respond error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 💬 Obtener respuestas de un check-in
 */
app.get("/checkins/:id/responses", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `
      SELECT *
      FROM awareness_checkin_responses
      WHERE checkin_id = $1
      ORDER BY created_at ASC
      `,
      [id],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /checkins/:id/responses error:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/**
 * 🌿 Archivar awareness item
 */
app.patch("/awareness/:id/archive", async (req, res) => {
  const { id } = req.params;

  try {
    await db.query(
      `
      UPDATE awareness_items
      SET archived = true,
          updated_at = NOW()
      WHERE id = $1
      `,
      [id],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Error archiving awareness item:", err);
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
  console.log(`Local: http://localhost:${PORT}/health`);
  console.log("=================================");
});