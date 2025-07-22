import { ApiProperty } from "@nestjs/swagger"
import { IsNotEmpty, IsString } from "class-validator"

export class GithubLoginDTO {
  @ApiProperty({
    description: "The redirect URL after GitHub OAuth",
    example: process.env.CLIENT_URL ?? "https://yourapp.com"
  })
  @IsString()
  @IsNotEmpty()
  redirect_url: string
}

export class GithubLoginResDTO {
  @ApiProperty({
    description: "The URL to redirect the user for GitHub OAuth",
    example:
      "https://github.com/login/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI"
  })
  url: string
}

export class GithubCallbackDTO {
  @ApiProperty({
    description: "The code received from GitHub after authorization",
    example: "abc123xyz456"
  })
  @IsString()
  @IsNotEmpty()
  code: string

  @ApiProperty({
    description: "The state parameter to prevent CSRF attacks",
    example: "random_state_string"
  })
  @IsString()
  @IsNotEmpty()
  state: string
}
