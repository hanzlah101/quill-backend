export const ERROR_CODES = {
  INVALID_CREDENTIALS: {
    status: 400,
    error: "Bad Request",
    message: "Invalid credentials"
  },
  EMAIL_ALREADY_VERIFIED: {
    status: 400,
    error: "Bad Request",
    message: "Email already verified"
  },
  EMAIL_NOT_VERIFIED: {
    status: 403,
    error: "Forbidden",
    message: "Email not verified"
  },
  INVALID_VERIFICATION_CODE: {
    status: 400,
    error: "Bad Request",
    message: "Invalid verification code"
  },
  INVALID_RESET_TOKEN: {
    status: 400,
    error: "Bad Request",
    message: "Invalid reset password token"
  },
  INCORRECT_CURRENT_PASSWORD: {
    status: 400,
    error: "Bad Request",
    message: "Current password is incorrect"
  },
  ACCOUNT_LINKED_TO_SOCIAL: {
    status: 400,
    error: "Bad Request",
    message: "This user is linked to a social account"
  },
  ALREADY_LOGGED_IN: {
    status: 403,
    error: "Forbidden",
    message: "User already logged in"
  },
  USER_ALREADY_EXISTS: {
    status: 409,
    error: "Conflict",
    message: "User already exists"
  },
  VALIDATION_FAILED: {
    status: 422,
    error: "Unprocessable Entity",
    message: "Validation failed"
  },
  UNAUTHORIZED: {
    status: 401,
    error: "Unauthorized",
    message: "Unauthorized"
  },
  SAME_NEW_PASSWORD: {
    status: 422,
    error: "Unprocessable Entity",
    message: "New password cannot be the same as current"
  },
  INTERNAL_SERVER_ERROR: {
    status: 500,
    error: "Internal Server Error",
    message: "Internal server error"
  }
}

export type ErrorCode = keyof typeof ERROR_CODES
