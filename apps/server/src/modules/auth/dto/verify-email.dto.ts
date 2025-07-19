import { ApiProperty } from "@nestjs/swagger"
import { IsString, Matches } from "class-validator"

export class VerifyEmailDTO {
  @ApiProperty({
    description: "The verification token sent to the user's email",
    example: "890321",
    minLength: 6,
    maxLength: 6
  })
  @IsString()
  @Matches(/^\d{6}$/, { message: "Invalid verification code" })
  token: string
}
