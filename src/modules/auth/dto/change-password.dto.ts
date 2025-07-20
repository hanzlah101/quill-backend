import { ApiProperty } from "@nestjs/swagger"
import { ResetPasswordDTO } from "./reset-password.dto"
import { IsString, MaxLength, MinLength } from "class-validator"

export class ChangePasswordDTO extends ResetPasswordDTO {
  @ApiProperty({
    description: "The current password of the user",
    example: "Str0ngP@ssword!",
    minLength: 1,
    maxLength: 128
  })
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  currentPassword: string
}
