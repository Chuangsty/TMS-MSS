import bcrypt from "bcryptjs";
import { pool } from "../config/db.js";

/*
Pasword policy:
    1) Minimum 8 characters and maximum 10 characters
    2) Comprise of alphabets , numbers, and special character */
function validatePassword(pw) {
  if (typeof pw !== "string") return "Password must be a string";
  if (pw.length < 8 || pw.length > 10) return "Password must be 8-10 characters long";
  if (!/[A-Za-z]/.test(pw)) return "Password must include a letter";
  if (!/[0-9]/.test(pw)) return "Password must include a number";
  if (!/[^A-Za-z0-9]/.test(pw)) return "Password must include a special character";
  // e.g. [^abc] = any character that is NOT a, b, or c
  return null; // Return null as no error in pw
}

function validateEmail(email) {
  if (typeof email !== "string" || email.trim() === "") return "Email is required";
  // trim() removes whitespace from the beginning and end of a string. e.g. (spaces " ", tabs \t, new lines \n)
  if (!/^\S+@\S+\.\S+$/.test(email)) return "Email format is invalid"; // !regex.test(email)
  return null;
}

// ADMIN: list users (no password hash returned) for admin onboarding dashboard
export async function lisUsersService() {
  // Displaying users base on date created
  const [rows] = await pool.query(
    `SELECT u.id, u.username, u.email, s.slug AS status, u.created_on
        FROM users u
        JOIN account_status s ON s.id = u.account_status_id
        ORDER BY u.created_on ASC`,
  );

  // Role(s) assignment
  const [roleRows] = await pool.query(
    `SELECT ur.user_id, r_slug
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id`,
  );

  const roleMap = new Map(); /* Map is a special JS obj used to store key -> value.
                                e.g. roleMap.set(1, ["ADMIN", "USER"]);   ===>   User 1 → ["ADMIN", "USER"] */
  // Loop through each row of DB
  for (const rr of roleRows) {
    if (!roleMap.has(rr.user_id)) roleMap.set(rr.user_id, []); // Check if user exist in map (if roleMap do not have user, create an empty array for them e.g. (1, []))
    roleMap.get(rr.user_id).push(rr.slug); // Push role(array stored for the user) into the created array
  }

  return {
    users: rows.map((u) => ({
      /*
    rows will show the users as query at the start e.g. { id: 1, username: "alice", email: "a@email.com" }
    .map() loops through each u user in rows and returns a new transformed array */

      ...u, // Copies all properties from u into the new object into { ...u }
      roles: roleMap.get(u.id) || [], // Look up this user's roles from roleMap and use them if found || else use empty array
    })),
  };

  // Admin onboarding of users + role assignment: e.g. { username, email, password, roles: ["DEVELOPER"] }
  export async function createUserService({ username, email, password, roles = [] }) {
    if (!username || typeof username !== "string") {
      const err = new Error("Username is required");
      err.status = 400;
      throw err;
    }

    const emailErr = validateEmail(email);
    if (emailErr) {
      const err = new Error(emailErr);
      err.status = 400;
      throw err;
    }

    const pwErr = validatePassword(password);
    if (pwErr) {
      const err = new Error(pwErr);
      err.status = 400;
      throw err;
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Ensure username unique
      const [existingUser] = await conn.query("SELECT id FROM users WHERE username = ? LIMIT 1", [username]);
      if (existingUser.length > 0) {
        const err = new Error("Username already exists");
        err.status = 409;
        throw err;
      }

      // Ensure email unique
      const [existingEmail] = await conn.query("SELECT id FROM users WHERE email = ? LIMIT 1", [email]);
      if (existingEmail.length > 0) {
        const err = new Error("Email already exists");
        err.status = 409;
        throw err;
      }

      // Set DEFAULT ACTIVE status ID
      const [[activeStatus]] = await conn.query("SELECT id FROM account_status WHERE slug = 'ACTIVE' LIMIT 1");
      if (!activeStatus) {
        const err = new Error("ACTIVE status missing. Seed lookups first.");
        err.status = 500;
        throw err;
      }

      // Role(s) is/are mandatory & must not be an empty array
      if (!Array.isArray(roles) || roles.length === 0) {
        const err = new Error("At least one role is required");
        err.status = 400;
        throw err;
      }

      const password_hash = await bcrypt.hash(password, 10);

      // Create user
      const [insertRes] = await conn.query(
        `INSERT INTO users (username, email, password_hash, account_status_id)
        VALUES (?, ?, ?, ?)`,
        [username, email, password_hash, activeStatus.id],
      );

      // Auto generate a user ID from inserting result from onboarding
      const newUserId = insertRes.insertId;

      // Fetching all existing roles in one query
      const [dbRoles] = await conn.query(
        `SELECT id, slug FROM roles WHERE slug IN (?)`,
        // We use WHERE slug IN (?) to fetch multiple roles at once
        // This avoids querying the database inside a loop (more efficient)
        [roles],
      );

      // Check if any submitted roles do not exist (for security: protect data integrity, avoiding malicious request)
      if (dbRoles.length !== roles.length) {
        // If number of roles fetched from DB != to number of roles submitted, it means some roles are invalid

        // Create a Set of valid role slugs from database
        const found = new Set(dbRoles.map((r) => r.slug));

        // Find which roles were submitted but not found
        const unknown = roles.filter((r) => !found.has(r));

        const err = new Error(`Unknown role(s): ${unknown.join(", ")}`);
        err.status = 400; // Bad Request
        throw err;
      }

      // Insert roles into user_roles table
      for (const r of dbRoles) {
        await conn.query(
          // IGNORE prevent duplicates
          `INSERT IGNORE INTO user_roles (user_id, role_id)
            VALUES (?, ?)`,
          [newUserId, r.id],
        );
      }

      await conn.commit();

      return {
        message: "User created",
        user: {
          id: newUserId,
          username,
          email,
          roles,
          status: "ACTIVE",
        },
      };
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  }

  // ADMIN:diable user (no delete)
}
