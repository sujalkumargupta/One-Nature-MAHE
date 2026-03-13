import { Hono } from "hono";
import { cors } from "hono/cors";
import { sign, verify } from "hono/jwt";

import * as jpeg from "jpeg-js";
import * as bcrypt from "bcryptjs";

type Env = {
  DB: D1Database;
  TURNSTILE_SECRET_KEY?: string;
  JWT_SECRET?: string;
};


const app = new Hono<{ Bindings: Env; Variables: { user?: any } }>();

app.use("/*", cors());

// JWT Secret - Read from Cloudflare secret (set via: npx wrangler secret put JWT_SECRET)
const getJwtSecret = (c: any) => c.env.JWT_SECRET || "your-secret-key-change-in-production";

// Auth middleware
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const token = authHeader.substring(7);
  try {
    const payload = await verify(token, getJwtSecret(c));
    c.set("user", payload);
    await next();
  } catch (err) {
    return c.json({ error: "Invalid token" }, 401);
  }
};

// Admin middleware
const adminMiddleware = async (c: any, next: any) => {
  const user = c.get("user");
  if (!user || user.role !== "admin") {
    return c.json({ error: "Admin access required" }, 403);
  }
  await next();
};

// Moderator middleware - allows moderator or admin
const moderatorMiddleware = async (c: any, next: any) => {
  const user = c.get("user");
  if (!user || (user.role !== "admin" && user.role !== "moderator")) {
    return c.json({ error: "Moderator or admin access required" }, 403);
  }
  await next();
};

const VALID_ROLES = ["user", "moderator", "admin"];

// Auth routes
app.post("/api/auth/login", async (c) => {
  const db = c.env.DB;
  const { username, password, turnstileToken } = await c.req.json();

  // Verify Turnstile Token if secret key is provided
  if (c.env.TURNSTILE_SECRET_KEY) {
    if (!turnstileToken) {
      return c.json({ error: "Please complete the 'not a robot' check" }, 400);
    }

    const formData = new FormData();
    formData.append("secret", c.env.TURNSTILE_SECRET_KEY);
    formData.append("response", turnstileToken);
    formData.append("remoteip", c.req.header("CF-Connecting-IP") || "");

    const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    const result = await fetch(url, {
      body: formData,
      method: "POST",
    });

    const outcome: any = await result.json();
    if (!outcome.success) {
      return c.json({ error: "Invalid captcha response. Please try again." }, 400);
    }
  }

  const user: any = await db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).bind(username).first();

  if (!user) {
    return c.json({ error: "Invalid credentials" }, 401);
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    return c.json({ error: "Invalid credentials" }, 401);
  }

  const token = await sign(
    { id: user.id, username: user.username, role: user.role },
    getJwtSecret(c)
  );

  return c.json({
    token,
    user: { id: user.id, username: user.username, role: user.role }
  });
});

app.get("/api/auth/me", authMiddleware, async (c) => {
  const user = c.get("user");
  return c.json({ user });
});

app.post("/api/auth/register", authMiddleware, adminMiddleware, async (c) => {
  const db = c.env.DB;
  const { username, password, role } = await c.req.json();

  // Validate role
  const assignedRole = role || "user";
  if (!VALID_ROLES.includes(assignedRole)) {
    return c.json({ error: "Invalid role. Must be user, moderator, or admin" }, 400);
  }

  // Check if user exists
  const existingUser = await db.prepare(
    "SELECT id FROM users WHERE username = ?"
  ).bind(username).first();

  if (existingUser) {
    return c.json({ error: "Username already exists" }, 400);
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const result = await db.prepare(
    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
  ).bind(username, passwordHash, assignedRole).run();

  const newUser: any = await db.prepare(
    "SELECT id, username, role, created_at FROM users WHERE id = ?"
  ).bind(result.meta.last_row_id).first();

  return c.json({ user: newUser }, 201);
});

app.get("/api/auth/users", authMiddleware, adminMiddleware, async (c) => {
  const db = c.env.DB;
  const { results } = await db.prepare(
    "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC"
  ).all();

  return c.json(results);
});

// Delete user - Admin only
app.delete("/api/auth/users/:id", authMiddleware, adminMiddleware, async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");

  // Prevent admin from deleting themselves
  const currentUser = c.get("user");
  if (currentUser.id === parseInt(id)) {
    return c.json({ error: "You cannot delete your own account" }, 400);
  }

  await db.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  return c.json({ success: true });
});

// Helper to compress image and return as Base64 string directly
async function compressAndUpload(base64Data: string): Promise<string | null> {
  if (!base64Data || !base64Data.startsWith("data:image")) {
    return base64Data; // Already a URL or null
  }

  try {
    const [header, data] = base64Data.split(",");
    const binaryData = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
    const mimeType = header.match(/:(.*?);/)?.[1] || "image/jpeg";

    let compressedBuffer: ArrayBuffer;

    if (mimeType === "image/jpeg" || mimeType === "image/jpg") {
      // Compress JPEG
      const rawImageData = jpeg.decode(binaryData);
      const compressed = jpeg.encode(rawImageData, 75); // 75% quality
      compressedBuffer = compressed.data.buffer;
    } else {
      // For other types, just use as is
      compressedBuffer = binaryData.buffer;
    }

    // Convert back to base64
    const compressedBinary = new Uint8Array(compressedBuffer);
    const compressedBase64 = btoa(
      compressedBinary.reduce((data, byte) => data + String.fromCharCode(byte), "")
    );

    return `data:image/jpeg;base64,${compressedBase64}`;
  } catch (err) {
    console.error("Compression failed:", err);
    return base64Data; // Fallback to original base64 if compression fails
  }
}

// Update user password - Admin only
app.patch("/api/auth/users/:id/password", authMiddleware, adminMiddleware, async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");
  const { password } = await c.req.json();

  if (!password || password.length < 6) {
    return c.json({ error: "Password must be at least 6 characters" }, 400);
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await db.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .bind(passwordHash, id)
    .run();

  return c.json({ success: true });
});

// Update user role - Admin only
app.patch("/api/auth/users/:id/role", authMiddleware, adminMiddleware, async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");
  const { role } = await c.req.json();

  if (!role || !VALID_ROLES.includes(role)) {
    return c.json({ error: "Invalid role. Must be user, moderator, or admin" }, 400);
  }

  // Prevent admin from changing their own role
  const currentUser = c.get("user");
  if (currentUser.id === parseInt(id)) {
    return c.json({ error: "You cannot change your own role" }, 400);
  }

  await db.prepare("UPDATE users SET role = ? WHERE id = ?")
    .bind(role, id)
    .run();

  return c.json({ success: true });
});

// Get all animals
app.get("/api/animals", async (c) => {
  const db = c.env.DB;
  const { results } = await db.prepare(
    "SELECT * FROM animals ORDER BY created_at DESC"
  ).all();

  return c.json(results.map((animal: any) => ({
    ...animal,
    caregiver_name: animal.caregiver_name_1,
    caregiver_mobile: animal.caregiver_mobile,
    caregiver_email: animal.caregiver_name_2,
    caregiver_name_1: undefined,
    caregiver_name_2: undefined
  })));
});

// Get single animal
app.get("/api/animals/:id", async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");

  const animal = await db.prepare(
    "SELECT * FROM animals WHERE id = ?"
  ).bind(id).first();

  if (!animal) {
    return c.json({ error: "Animal not found" }, 404);
  }

  return c.json({
    ...animal,
    is_neutered: animal.is_neutered === 1,
    caregiver_name: animal.caregiver_name_1,
    caregiver_mobile: animal.caregiver_mobile,
    caregiver_email: animal.caregiver_name_2,
    caregiver_name_1: undefined,
    caregiver_name_2: undefined
  });
});

// Create animal - Require authentication (User or Admin)
app.post("/api/animals", authMiddleware, async (c) => {
  const db = c.env.DB;
  const body = await c.req.json();

  // Compress image to store as Base64 format in DB directly
  const photoUrl = await compressAndUpload(body.photo_url);

  const result = await db.prepare(`
    INSERT INTO animals (
      photo_url, animal_type, name, age, gender, is_neutered,
      vaccination_status, area_of_living, nature, college_campus,
      caregiver_name_1, caregiver_name_2, caregiver_mobile
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    photoUrl,
    body.animal_type,
    body.name,
    body.age,
    body.gender,
    body.is_neutered ? 1 : 0,
    body.vaccination_status,
    body.area_of_living,
    body.nature,
    body.college_campus,
    body.caregiver_name || null,
    body.caregiver_email || null,
    body.caregiver_mobile || null
  ).run();

  const newAnimal = await db.prepare(
    "SELECT * FROM animals WHERE id = ?"
  ).bind(result.meta.last_row_id).first();

  if (!newAnimal) {
    return c.json({ error: "Failed to create animal" }, 500);
  }

  return c.json({
    ...newAnimal,
    is_neutered: newAnimal.is_neutered === 1,
    caregiver_name: newAnimal.caregiver_name_1,
    caregiver_mobile: newAnimal.caregiver_mobile,
    caregiver_email: newAnimal.caregiver_name_2,
    caregiver_name_1: undefined,
    caregiver_name_2: undefined
  }, 201);
});

// Update animal - Require moderator or admin
app.put("/api/animals/:id", authMiddleware, moderatorMiddleware, async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");
  const body = await c.req.json();

  // Compress image to store as Base64 format in DB directly
  const photoUrl = await compressAndUpload(body.photo_url);

  await db.prepare(`
    UPDATE animals SET
      photo_url = ?,
      animal_type = ?,
      name = ?,
      age = ?,
      gender = ?,
      is_neutered = ?,
      vaccination_status = ?,
      area_of_living = ?,
      nature = ?,
      college_campus = ?,
      caregiver_name_1 = ?,
      caregiver_name_2 = ?,
      caregiver_mobile = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(
    photoUrl,
    body.animal_type,
    body.name,
    body.age,
    body.gender,
    body.is_neutered ? 1 : 0,
    body.vaccination_status,
    body.area_of_living,
    body.nature,
    body.college_campus,
    body.caregiver_name || null,
    body.caregiver_email || null,
    body.caregiver_mobile || null,
    id
  ).run();

  const updatedAnimal = await db.prepare(
    "SELECT * FROM animals WHERE id = ?"
  ).bind(id).first();

  if (!updatedAnimal) {
    return c.json({ error: "Animal not found" }, 404);
  }

  return c.json({
    ...updatedAnimal,
    is_neutered: updatedAnimal.is_neutered === 1,
    caregiver_name: updatedAnimal.caregiver_name_1,
    caregiver_mobile: updatedAnimal.caregiver_mobile,
    caregiver_email: updatedAnimal.caregiver_name_2,
    caregiver_name_1: undefined,
    caregiver_name_2: undefined
  });
});

// Delete animal - Require moderator or admin
app.delete("/api/animals/:id", authMiddleware, moderatorMiddleware, async (c) => {
  const db = c.env.DB;
  const id = c.req.param("id");

  await db.prepare(
    "DELETE FROM animals WHERE id = ?"
  ).bind(id).run();

  return c.json({ success: true });
});

export default app;
