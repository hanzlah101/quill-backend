import { ApiProperty } from "@nestjs/swagger"

export class UserDTO {
  @ApiProperty({
    description: "Unique identifier of the user",
    example: "clx12abc0000xyz1234"
  })
  id: string

  @ApiProperty({
    description: "The name of the user",
    example: "John Doe"
  })
  name: string

  @ApiProperty({
    description: "The email of the user",
    example: "user@example.com"
  })
  email: string

  @ApiProperty({
    example: false,
    description: "Indicates whether the user's email is verified"
  })
  emailVerified: boolean

  @ApiProperty({
    description: "The time when the user was created",
    example: "2024-01-01T00:00:00.000Z"
  })
  createdAt: Date

  @ApiProperty({
    description: "The time when the user was last updated",
    example: "2024-01-01T00:00:00.000Z"
  })
  updatedAt: Date
}
