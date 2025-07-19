import { ApiProperty } from "@nestjs/swagger"
import { IsEmail, MaxLength, MinLength } from "class-validator"

export class LoginDTO {
  @ApiProperty({
    example: "john@example.com",
    description: "Email address used for login",
    minLength: 1,
    maxLength: 320
  })
  @IsEmail()
  @MaxLength(320)
  readonly email: string

  @ApiProperty({
    example: "Str0ngP@ssword!",
    description: "Password used for login",
    minLength: 1,
    maxLength: 128
  })
  @MinLength(1)
  @MaxLength(128)
  readonly password: string
}
