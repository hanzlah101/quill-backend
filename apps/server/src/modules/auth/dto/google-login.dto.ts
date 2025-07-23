import { ApiProperty } from "@nestjs/swagger"
import { IsNotEmpty, IsString } from "class-validator"

export class GoogleLoginDTO {
  @ApiProperty({
    description: "The redirect URL after Google OAuth",
    example: process.env.CLIENT_URL ?? "https://yourapp.com"
  })
  @IsString()
  @IsNotEmpty()
  redirect_url: string
}

export class GoogleCallbackDTO {
  @ApiProperty({
    description: "The authorization code received from Google OAuth",
    example: "4/0AY0e-g5..."
  })
  @IsString()
  @IsNotEmpty()
  code: string

  @ApiProperty({
    description: "The state parameter to verify the callback",
    example: "state123"
  })
  @IsString()
  @IsNotEmpty()
  state: string

  @ApiProperty({
    description: "The scope of access requested",
    example: "openid+profile"
  })
  @IsString()
  scope?: string | null

  @ApiProperty({
    description: "The prompt for the OAuth flow",
    example: "consent"
  })
  @IsString()
  prompt?: string | null

  @ApiProperty({
    description: "The user ID of the authenticated user",
    example: "1234567890"
  })
  @IsString()
  authuser?: string | null
}

export class GoogleLoginResDTO {
  @ApiProperty({
    description: "The URL to redirect the user to for Google OAuth",
    example: "https://accounts.google.com/o/oauth2/auth?client_id=..."
  })
  url: string
}
