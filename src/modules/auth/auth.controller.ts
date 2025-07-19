import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards
} from "@nestjs/common"
import { AuthService } from "./auth.service"
import { ApiBody, ApiResponse, ApiTags } from "@nestjs/swagger"
import { SignUpDTO } from "./dto/sign-up.dto"
import { UserDTO } from "./dto/user.dto"
import { LoginDTO } from "./dto/login.dto"
import { Request, Response } from "express"
import { AuthGuard } from "@/guards/auth.guard"
import { GuestGuard } from "@/guards/guest.guard"
import { CheckEmailVerification } from "@/decorators/email-verification.decorator"
import { Session, User } from "@/decorators/session.decorator"
import { SESSION_COOKIE_NAME } from "@/utils/constants"
import { VerifyEmailDTO } from "./dto/verify-email.dto"

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("sign-up")
  @UseGuards(GuestGuard)
  @HttpCode(201)
  @ApiBody({ type: SignUpDTO })
  @ApiResponse({
    status: 201,
    description: "User successfully created",
    type: UserDTO
  })
  @ApiResponse({ status: 422, description: "Validation failed" })
  @ApiResponse({ status: 409, description: "User already exists" })
  @ApiResponse({ status: 403, description: "Already logged in" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  async signUp(
    @Body() body: SignUpDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<UserDTO> {
    const user = await this.authService.signUp(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @Post("verify-code")
  @UseGuards(AuthGuard)
  @CheckEmailVerification(false)
  @HttpCode(204)
  @ApiBody({ type: VerifyEmailDTO })
  @ApiResponse({
    status: 204,
    description: "Email verified successfully"
  })
  @ApiResponse({
    status: 400,
    description: "Invalid or expired verification code"
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async verifyEmail(@User() user: UserDTO, @Body() body: VerifyEmailDTO) {
    await this.authService.verifyEmail(user, body.token)
  }

  @Post("resend-email")
  @UseGuards(AuthGuard)
  @CheckEmailVerification(false)
  @HttpCode(204)
  @ApiResponse({
    status: 204,
    description: "Verification email sent successfully"
  })
  @ApiResponse({ status: 400, description: "Email already verified" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async resendVerificationEmail(@User() user: UserDTO) {
    await this.authService.resendVerificationEmail(user)
  }

  @Post("login")
  @UseGuards(GuestGuard)
  @HttpCode(200)
  @ApiBody({ type: LoginDTO })
  @ApiResponse({
    status: 200,
    description: "User successfully logged in",
    type: UserDTO
  })
  @ApiResponse({ status: 422, description: "Validation failed" })
  @ApiResponse({ status: 403, description: "Already logged in" })
  @ApiResponse({ status: 400, description: "Invalid credentials" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  async login(
    @Body() body: LoginDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<UserDTO> {
    const user = await this.authService.login(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @Post("logout")
  @HttpCode(204)
  @UseGuards(AuthGuard)
  @ApiResponse({
    status: 204,
    description: "User successfully logged out"
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async logout(
    @Session() session: Express.Session,
    @Res({ passthrough: true }) res: Response
  ) {
    await this.authService.logout(session.id)
    res.clearCookie(SESSION_COOKIE_NAME)
  }

  @Get("me")
  @UseGuards(AuthGuard)
  @CheckEmailVerification(false)
  @ApiResponse({
    status: 200,
    description: "Returns the current user",
    type: UserDTO
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  me(@User() user: Express.User) {
    return user
  }
}
