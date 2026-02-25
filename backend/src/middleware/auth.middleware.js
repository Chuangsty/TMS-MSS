import jwt from "jsonwebtoken";
import { pool } from "../config/db.js";

// Protect routes: requires valid bearer(whoever bears(carries) the token) & token
export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || ""; // Reads the Authorization header
    const [type, token] = header.split(" "); // Split header into type and token by space (" ")

    if (type !== "Bearer" || !token) {
      const err = new Error("Missing or invalid Authorization header");
      err.status = 401;
      throw err;
    }

    // Verify token signature + expiry (token & JWT_SECRET) for all actions below
    const jwtData = jwt.verify(token, process.env.JWT_SECRET);

    // Load latest user status from DB (role updates/disabled users take effect immediately)
    const [userInfo] = await pool.query(
      `SELECT 
                u.id,
                u.username,
                u.email,
                s.slug AS status_slug
            FROM users u
            JOIN account_status s ON s.id = u.account_status_id
            WHERE u.id = ?
            LIMIT 1`,
      [jwtData.userId], // Passing the decoded value into your SQL query as a parameter (use the userId stored inside the verified token)
    );
    // Return something like userInfo = [{ id: 1, username: "chuang", email: "chuang@email.com", status_slug: "ACTIVE"}];

    // If userInfo contains nothing
    if (userInfo.length === 0) {
      const err = new Error("Invalid token user");
      err.status = 401;
      throw err;
    }
    const user = userInfo[0];

    // Prevents disabled account from using still-valid tokens
    if (user.status_slug !== "ACTIVE") {
      const err = new Error("Account is disabled");
      err.status = 403;
      throw err;
    }

    // Load roles
    const [roleUserInfo] = await pool.query(
      `SELECT r.slug
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = ?`,
      [user.id],
    );

    // Attach to request for downstream use
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      roles: roleUserInfo.map((r) => r.slug),
    };

    next();
  } catch (err) {
    err.status = err.status || 401;
    next(err);
  }
}
