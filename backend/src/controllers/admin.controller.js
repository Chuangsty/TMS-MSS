import { listUsersService, adminCreateUserService, adminUpdateUserService } from "../services/admin.service.js";

// Admin: Users List
export async function listUsersController(req, res, next) {
  try {
    const result = await listUsersService(); // or pass filters if you have
    res.json(result);
  } catch (err) {
    next(err);
  }
}

// ADMIN: User Creation
export async function adminCreateUserController(req, res, next) {
  try {
    const { username, email, password, roles } = req.body;

    const result = await adminCreateUserService({ username, email, password, roles });

    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
}

// ADMIN: User Update
export async function adminUpdateUserController(req, res, next) {
  try {
    const targetUserId = Number(req.params.id);
    const actorUserId = req.user.id;

    const { username, email, status, roles, newPassword } = req.body;

    const result = await adminUpdateUserService({
      targetUserId,
      actorUserId,
      patch: { username, email, status, roles, newPassword },
    });

    res.json(result);
  } catch (err) {
    next(err);
  }
}
