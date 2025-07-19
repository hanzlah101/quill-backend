import { SetMetadata } from "@nestjs/common"

export const EMAIL_VERIFIED_KEY = "emailVerified"
export const CheckEmailVerification = (shouldCheck = true) =>
  SetMetadata(EMAIL_VERIFIED_KEY, shouldCheck)
