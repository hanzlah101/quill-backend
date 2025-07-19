import { Match } from "@/decorators/match.decorator"
import { ApiProperty } from "@nestjs/swagger"
import {
  IsEmail,
  IsString,
  IsStrongPassword,
  MaxLength,
  MinLength
} from "class-validator"

export class ResetPasswordRequestDTO {
  @ApiProperty({
    description: "The email address of the user requesting the password reset",
    example: "user@example.com"
  })
  @IsString()
  @MinLength(1)
  @MaxLength(320)
  @IsEmail()
  email: string
}

export class ResetPasswordDTO {
  @ApiProperty({
    description: "The new password to set",
    example: "NewStr0ngP@ssword!",
    minLength: 8,
    maxLength: 128
  })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @IsStrongPassword()
  newPassword: string

  @ApiProperty({
    description: "Confirmation of the new password",
    example: "NewStr0ngP@ssword!",
    minLength: 1,
    maxLength: 128
  })
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  @Match("newPassword", { message: "Passwords don't match" })
  confirmPassword: string
}
