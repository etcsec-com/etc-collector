import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

/**
 * Winston Logger Configuration
 * Structured JSON logging with file rotation
 */

const isDevelopment = process.env['NODE_ENV'] === 'development';
const logLevel = process.env['LOG_LEVEL'] ?? 'info';

// Custom format to redact sensitive data
const redactSensitiveData = winston.format((info) => {
  const sensitiveFields = [
    'password',
    'bindPassword',
    'clientSecret',
    'token',
    'privateKey',
    'secret',
  ];

  const visited = new WeakSet();

  const redact = (obj: Record<string, unknown>): void => {
    // Prevent circular reference infinite loops
    if (visited.has(obj)) return;
    visited.add(obj);

    for (const key in obj) {
      if (sensitiveFields.some((field) => key.toLowerCase().includes(field.toLowerCase()))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
        redact(obj[key] as Record<string, unknown>);
      }
    }
  };

  redact(info);
  return info;
});

// Transport configuration
const transports: winston.transport[] = [
  // Console transport
  new winston.transports.Console({
    format: isDevelopment
      ? winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      : winston.format.json(),
  }),
];

// File transports for production
if (!isDevelopment) {
  transports.push(
    // Error log
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '14d',
      zippedArchive: true,
    }),
    // Combined log
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      zippedArchive: true,
    })
  );
}

// Create logger instance
export const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    redactSensitiveData(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports,
  exitOnError: false,
});

// Helper methods for structured logging
export const logInfo = (message: string, metadata?: Record<string, unknown>): void => {
  logger.info(message, metadata);
};

export const logError = (message: string, error?: Error, metadata?: Record<string, unknown>): void => {
  logger.error(message, {
    ...metadata,
    error: error?.message,
    stack: error?.stack,
  });
};

export const logWarn = (message: string, metadata?: Record<string, unknown>): void => {
  logger.warn(message, metadata);
};

export const logDebug = (message: string, metadata?: Record<string, unknown>): void => {
  logger.debug(message, metadata);
};

/**
 * Enable verbose/debug logging at runtime
 * Used by --verbose flag
 */
export const setVerbose = (enabled: boolean): void => {
  if (enabled) {
    logger.level = 'debug';
    // Also update console transport to use simple format for readability
    logger.transports.forEach((transport) => {
      if (transport instanceof winston.transports.Console) {
        transport.format = winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: 'HH:mm:ss' }),
          winston.format.printf(({ level, message, timestamp, ...meta }) => {
            const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
            return `[${timestamp}] ${level}: ${message}${metaStr}`;
          })
        );
      }
    });
    logger.debug('Verbose logging enabled');
  }
};
