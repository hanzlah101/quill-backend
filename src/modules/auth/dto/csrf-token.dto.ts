import { ApiProperty } from "@nestjs/swagger"
import { IsString } from "class-validator"

export class CSRFTokenDTO {
  @ApiProperty({
    description: "CSRF token for the current session",
    example: "abc123xyz45692309092.293092039203"
  })
  @IsString()
  csrfToken: string
}
