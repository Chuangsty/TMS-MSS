import { loginService } from "../services/auth.service.js";

// Controller: handles HTTP layer only
export async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const result = await loginService({ email, password });
    res.json(result);
  } catch (err) {
    next(err);
  }
}
