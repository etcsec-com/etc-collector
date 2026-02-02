import rateLimit from 'express-rate-limit';

/**
 * Rate limiting configuration
 */

// General API rate limit: 100 requests per minute
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Audit endpoint rate limit: 10 audits per 5 minutes
export const auditLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10,
  message: {
    success: false,
    error: {
      code: 'AUDIT_RATE_LIMIT_EXCEEDED',
      message: 'Too many audit requests, please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});
