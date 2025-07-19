import { ApiProperty } from "@nestjs/swagger"
import {
  IsEmail,
  IsStrongPassword,
  MaxLength,
  MinLength
} from "class-validator"

import { Match } from "@/decorators/match.decorator"

export class SignUpDTO {
  @ApiProperty({
    example: "John Doe",
    description: "Full name of the user",
    minLength: 1,
    maxLength: 255
  })
  @MinLength(1)
  @MaxLength(255)
  readonly name: string

  @ApiProperty({
    example: "john@example.com",
    description: "Valid email address used for login and communication",
    minLength: 1,
    maxLength: 320
  })
  @IsEmail()
  @MaxLength(320)
  readonly email: string

  @ApiProperty({
    example: "Str0ngP@ssword!",
    description:
      "Strong password with at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
    minLength: 8,
    maxLength: 128
  })
  @MinLength(8)
  @MaxLength(128)
  @IsStrongPassword()
  readonly password: string

  @ApiProperty({
    example: "Str0ngP@ssword!",
    description: "Must match the password field exactly to confirm user intent"
  })
  @MinLength(1)
  @Match("password", { message: "Passwords don't match" })
  readonly confirmPassword: string
}
