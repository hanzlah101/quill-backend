export const ERROR_CODES = {
  INVALID_CREDENTIALS: {
    status: 400,
    message: "Invalid credentials"
  },
  EMAIL_ALREADY_VERIFIED: {
    status: 400,
    message: "Email already verified"
  },
  EMAIL_NOT_VERIFIED: {
    status: 403,
    message: "Email not verified"
  },
  EMAIL_NOT_FOUND: {
    status: 404,
    message: "User doesn't exist with this email"
  },
  INVALID_VERIFICATION_CODE: {
    status: 400,
    message: "Verification code is invalid or expired"
  },
  INVALID_RESET_TOKEN: {
    status: 400,
    message: "Password reset link is invalid or expired"
  },
  INCORRECT_CURRENT_PASSWORD: {
    status: 400,
    message: "Current password is incorrect"
  },
  ACCOUNT_LINKED_TO_SOCIAL: {
    status: 400,
    message: "This user is linked to a social account"
  },
  ALREADY_LOGGED_IN: {
    status: 403,
    message: "User already logged in"
  },
  USER_ALREADY_EXISTS: {
    status: 409,
    message: "User already exists"
  },
  VALIDATION_FAILED: {
    status: 422,
    message: "Validation failed"
  },
  UNAUTHORIZED: {
    status: 401,
    message: "Unauthorized"
  },
  SAME_NEW_PASSWORD: {
    status: 422,
    message: "New password cannot be the same as current"
  },
  EMAIL_SEND_FAILED: {
    status: 502,
    message: "Failed to send verification email"
  },
  INTERNAL_SERVER_ERROR: {
    status: 500,
    message: "Internal server error"
  }
}

export type ErrorCode = keyof typeof ERROR_CODES
