// When route doesn't exist / matches the URL
export function notFoundHandler(req, res, next) {
  res.status(404).json({ error: "Not Found" });
}

// Central error handler
export function errorHandler(err, req, res, next) {
  const status = err.status || 500;
  res.status(status).json({ error: err.message || "Server error" });
}
