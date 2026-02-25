// When no route matches the request URL
export function notFoundHandler(req, res, next) {
  res.status(404).json({ error: "Not Found" });
}

// Any error that is thrown in your backend logic
export function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  res.status(status).json({ error: err.message || "Server error" });
}
