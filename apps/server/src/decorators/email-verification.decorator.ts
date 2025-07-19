import { SetMetadata } from "@nestjs/common"

export const EMAIL_VERIFIED_KEY = "emailVerified"
export const CheckEmailVerification = (emailVerified: boolean) =>
  SetMetadata(EMAIL_VERIFIED_KEY, emailVerified)
