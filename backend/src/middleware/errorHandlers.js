function notFoundHandler(req, res, next) {
  res.status(404).json({
    success: false,
    error: 'Not found',
    path: req.originalUrl
  });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = Number(err.statusCode || err.status || 500);

  // Log full error server-side (good)
  console.error('Unhandled error:', {
    status,
    message: err.message,
    stack: err.stack,
    path: req.originalUrl
  });

  // Send real message to frontend (safe for your app)
  res.status(status).json({
    success: false,
    error: err.message || 'Internal server error',
    path: req.originalUrl
  });
}

module.exports = { notFoundHandler, errorHandler };
