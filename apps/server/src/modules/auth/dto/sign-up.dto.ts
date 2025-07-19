import { Match } from "@/decorators/match.decorator"
import { ApiProperty } from "@nestjs/swagger"
import {
  IsEmail,
  IsString,
  IsStrongPassword,
  MaxLength,
  MinLength
} from "class-validator"

export class SignUpDTO {
  @ApiProperty({
    example: "John Doe",
    description: "Full name of the user",
    minLength: 1,
    maxLength: 255
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  readonly name: string

  @ApiProperty({
    example: "john@example.com",
    description: "Valid email address used for login and communication",
    minLength: 1,
    maxLength: 320
  })
  @IsString()
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
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @IsStrongPassword()
  readonly password: string

  @ApiProperty({
    example: "Str0ngP@ssword!",
    description: "Must match the password field exactly to confirm user intent",
    minLength: 1,
    maxLength: 128
  })
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  @Match("password", { message: "Passwords don't match" })
  readonly confirmPassword: string
}
