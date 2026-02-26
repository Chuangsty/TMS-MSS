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
export async function listUsersService() {
  // Displaying users base on date created
  const [rows] = await pool.query(
    `SELECT u.id, u.username, u.email, s.slug AS status, u.created_at
        FROM users u
        JOIN account_status s ON s.id = u.account_status_id
        ORDER BY u.created_at ASC`,
  );

  // Role(s) assignment
  const [roleRows] = await pool.query(
    `SELECT ur.user_id, r.slug
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
}

// ADMIN: onboarding of users + role assignment: e.g. { username, email, password, roles }
export async function createUserService({ username, email, password, roles = [] }) {
  // Basic validation (keep it simple but safe)
  if (!username || !email || !password) {
    const err = new Error("username, email, and password are required");
    err.status = 400;
    throw err;
  }

  // Roles mandatory
  if (!Array.isArray(roles) || roles.length === 0) {
    const err = new Error("At least one role is required");
    err.status = 400;
    throw err;
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Set DEFAULT ACTIVE status ID
    const [[activeStatus]] = await conn.query(`SELECT id FROM account_status WHERE slug = 'ACTIVE' LIMIT 1`);
    // Throw err if "ACTIVE" status not found in seed
    if (!activeStatus) {
      const err = new Error("ACTIVE status not found in DB");
      err.status = 500;
      throw err;
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Create user
    const [insertRes] = await conn.query(
      `INSERT INTO users (username, email, password_hash, account_status_id)
       VALUES (?, ?, ?, ?)`,
      [username, email, password_hash, activeStatus.id],
    );
    // Auto generate a user ID from inserting result from onboarding
    const newUserId = insertRes.insertId;

    // Fetch selected roles in one query
    const [dbRoles] = await conn.query(`SELECT id, slug FROM roles WHERE slug IN (?)`, [roles]);
    // Validate role slugs exist
    if (dbRoles.length !== roles.length) {
      const found = new Set(dbRoles.map((r) => r.slug));
      const unknown = roles.filter((r) => !found.has(r));
      const err = new Error(`Unknown role(s): ${unknown.join(", ")}`);
      err.status = 400;
      throw err;
    }
    // Insert role links
    for (const r of dbRoles) {
      await conn.query(`INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)`, [newUserId, r.id]);
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

// ADMIN: update user state (no delete)
export async function userStatusService({ targetUserId, actorUserId, statusSlug }) {
  // Valid ID (prevent invalid or malicious input from reaching your database logic)
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    // Make sure targetUserId is a number and its not negative: proper default id number
    const err = new Error("Invalid user id");
    err.status = 400;
    throw err;
  }

  // Prevent admin from disabling themselves (safety)
  if (actorUserId === targetUserId) {
    const err = new Error("You cannot disable your own account as an ADMIN");
    err.status = 400;
    throw err;
  }
  // Validate requested status
  const allowed = new Set(["ACTIVE", "DISABLED"]);
  // Throw error if status not part of DB
  if (!allowed.has(statusSlug)) {
    const err = new Error("Invalid status (allowed: ACTIVE, DISABLED)");
    err.status = 400;
    throw err;
  }

  // Get status id from account_status table
  const [[statusRow]] = await pool.query("SELECT id FROM account_status WHERE slug = ? LIMIT 1", [statusSlug]);
  // If status id not found
  if (!statusRow) {
    const err = new Error(`Status ${statusSlug} not found. Seed account_status first.`);
    err.status = 500;
    throw err;
  }

  // Update user status
  const [res] = await pool.query("UPDATE users SET account_status_id = ? WHERE id = ?", [statusRow.id, targetUserId]);
  // If updated user not found
  if (res.affectedRows === 0) {
    const err = new Error("User not found");
    err.status = 404;
    throw err;
  }

  return { message: `User status updated to ${statusSlug}` };
}

// ADMIN: reset password (without changing user id)
export async function resetUserPasswordService({ targetUserId, newPassword }) {
  // Necessary validation (prevent invalid or malicious input from reaching your database logic)
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    // Make sure targetUserId is a number and its not negative: proper default id number
    const err = new Error("Invalid user id");
    err.status = 400;
    throw err;
  }

  // Throwing error with validatePassword function
  const pwErr = validatePassword(newPassword);
  if (pwErr) {
    const err = new Error(pwErr);
    err.status = 400;
    throw err;
  }

  // Hashing new password
  const password_hash = await bcrypt.hash(newPassword, 10);

  // Updating DB with new hashed password at target user
  const [res] = await pool.query("UPDATE users SET password_hash = ? WHERE id = ?", [password_hash, targetUserId]);
  // Throw error if the userId being updated doesn't match DB
  if (res.affectedRows === 0) {
    const err = new Error("User not found");
    err.status = 404;
    throw err;
  }

  // Success: password reset success message
  return { message: "Password reset successful" };
}

// ADMIN: assigning/removing role START ==================================================================
export async function updateUserRolesService({ targetUserId, roles }) {
  // Necessary user id validation (prevent invalid or malicious input from reaching your database logic)
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    // Make sure targetUserId is a number and its not negative: proper default id number
    const err = new Error("Invalid user id");
    err.status = 400;
    throw err;
  }

  // Role(s) is/are mandatory
  if (!roleSlug || typeof roleSlug !== "string") {
    const err = new Error("roleSlug is required");
    err.status = 400;
    throw err;
  }

  // Utilize transaction to have consistent inputs (prevent incomplete data insertion)
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) Ensure user exists
    const [userRows] = await pool.query("SELECT id FROM users WHERE id = ? LIMIT 1", [targetUserId]);
    // Throw error if the userId being selected doesn't match DB
    if (userRows.length === 0) {
      const err = new Error("User not found");
      err.status = 404;
      throw err;
    }

    // 2) Fetch roles in ONE query (same style as createUserService)
    const [dbRoles] = await conn.query("SELECT id, slug FROM roles WHERE slug IN (?)", [roles]);

    // 3) Validate unknown roles (security-first)
    if (dbRoles.length !== roles.length) {
      const found = new Set(dbRoles.map((r) => r.slug));
      const unknown = roles.filter((r) => !found.has(r));

      const err = new Error(`Unknown role(s): ${unknown.join(", ")}`);
      err.status = 400;
      throw err;
    }

    // 4) Replace roles: delete old → insert new
    await conn.query("DELETE FROM user_roles WHERE user_id = ?", [targetUserId]);

    for (const r of dbRoles) {
      await conn.query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", [targetUserId, r.id]);
    }

    await conn.commit();
    return { message: "User roles updated", roles };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
// ADMIN: assigning role END ====================================================================
