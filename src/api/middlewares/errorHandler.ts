import { Request, Response, NextFunction } from 'express';
import { BaseError } from '../../types/error.types';
import { logError } from '../../utils/logger';

/**
 * Centralized error handling middleware
 * Catches all errors and formats consistent error responses
 */
export const errorHandler = (
  error: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Log the error
  logError('Error caught by error handler', error, {
    path: _req.path,
    method: _req.method,
  });

  // Determine if this is an operational error
  const isOperational = error instanceof BaseError && error.isOperational;
  const statusCode = error instanceof BaseError ? error.statusCode : 500;

  // Determine error code
  const errorCode =
    error.name !== 'Error' ? error.name.replace(/([A-Z])/g, '_$1').toUpperCase() : 'INTERNAL_SERVER_ERROR';

  // Build error response
  const errorResponse: {
    success: false;
    error: {
      code: string;
      message: string;
      details?: unknown;
    };
  } = {
    success: false,
    error: {
      code: errorCode,
      message: error.message || 'An unexpected error occurred',
    },
  };

  // In development, include stack trace and additional details
  if (process.env['NODE_ENV'] === 'development') {
    errorResponse.error.details = {
      stack: error.stack,
      isOperational,
    };
  }

  res.status(statusCode).json(errorResponse);
};
