import {
  Body,
  Controller,
  Get,
  HttpCode,
  InternalServerErrorException,
  Param,
  Patch,
  Post,
  Req,
  Res,
  UseGuards
} from "@nestjs/common"
import { AuthService } from "./auth.service"
import {
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags
} from "@nestjs/swagger"
import { SignUpDTO } from "./dto/sign-up.dto"
import { UserDTO } from "./dto/user.dto"
import { LoginDTO } from "./dto/login.dto"
import { Request, Response } from "express"
import { AuthGuard } from "@/guards/auth.guard"
import { GuestGuard } from "@/guards/guest.guard"
import { CheckEmailVerification } from "@/decorators/email-verification.decorator"
import { Session, User } from "@/decorators/session.decorator"
import { COOKIES } from "@/utils/constants"
import { VerifyEmailDTO } from "./dto/verify-email.dto"
import { ChangePasswordDTO } from "./dto/change-password.dto"
import { CSRFTokenDTO } from "./dto/csrf-token.dto"
import {
  ResetPasswordDTO,
  ResetPasswordRequestDTO
} from "./dto/reset-password.dto"

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({
    summary: "Sign up a new user",
    description: "Creates a new user account and sends a verification email."
  })
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
  ) {
    const user = await this.authService.signUp(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @ApiOperation({
    summary: "Verify email",
    description: "Verifies the user's email using a verification code."
  })
  @Post("verify")
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
    await this.authService.verifyEmail(user, body.code)
  }

  @ApiOperation({
    summary: "Resend verification email",
    description: "Sends a new verification email to the user."
  })
  @Post("resend-verification")
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
    await this.authService.resendVerification(user)
  }

  @ApiOperation({
    summary: "Login user",
    description: "Logs in a user and creates a session."
  })
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
  ) {
    const user = await this.authService.login(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @ApiOperation({
    summary: "Request password reset",
    description: "Sends a password reset email to the user."
  })
  @Post("reset-password")
  @UseGuards(GuestGuard)
  @HttpCode(204)
  @ApiBody({ type: ResetPasswordRequestDTO })
  @ApiResponse({
    status: 204,
    description: "Password reset request successful"
  })
  @ApiResponse({ status: 422, description: "Validation failed" })
  @ApiResponse({ status: 400, description: "Invalid email address" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  async requestPasswordReset(@Body() body: ResetPasswordRequestDTO) {
    await this.authService.requestPasswordReset(body.email)
  }

  @ApiOperation({
    summary: "Reset password",
    description: "Resets the user's password using a reset token."
  })
  @Patch("reset-password/:token")
  @UseGuards(GuestGuard)
  @HttpCode(204)
  @ApiBody({ type: ResetPasswordDTO })
  @ApiParam({
    name: "token",
    description: "The password reset token",
    example: "abc123xyz456"
  })
  @ApiResponse({
    status: 204,
    description: "Password reset successful"
  })
  @ApiResponse({ status: 422, description: "Validation failed" })
  @ApiResponse({ status: 400, description: "Invalid reset token" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  async resetPassword(
    @Param("token") token: string,
    @Body() body: ResetPasswordDTO
  ) {
    await this.authService.resetPassword(token, body.newPassword)
  }

  @ApiOperation({
    summary: "Change password",
    description:
      "Changes the user's password after verifying the current password."
  })
  @Patch("change-password")
  @UseGuards(AuthGuard)
  @HttpCode(204)
  @ApiBody({ type: ChangePasswordDTO })
  @ApiResponse({
    status: 204,
    description: "Password changed successfully"
  })
  @ApiResponse({ status: 422, description: "Validation failed" })
  @ApiResponse({ status: 409, description: "Linked to a social account" })
  @ApiResponse({ status: 400, description: "Current password is incorrect" })
  @ApiResponse({ status: 500, description: "Internal server error" })
  async changePassword(
    @User() user: Express.User,
    @Body() body: ChangePasswordDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    await this.authService.changePassword(user.id, body)
    await this.authService.createSession(user.id, req, res)
  }

  @ApiOperation({
    summary: "Logout user",
    description: "Logs out the user and clears the session."
  })
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
    res.clearCookie(COOKIES.session)
    res.clearCookie(COOKIES.csrf)
  }

  @ApiOperation({
    summary: "Get CSRF token",
    description: "Returns the CSRF token for the current session."
  })
  @Get("csrf-token")
  @HttpCode(200)
  @ApiResponse({
    status: 200,
    description: "Returns the CSRF token",
    type: CSRFTokenDTO
  })
  @ApiResponse({ status: 500, description: "Internal server error" })
  getCsrfToken(@Req() req: Request) {
    if (!req.csrfToken) throw new InternalServerErrorException()
    return { csrfToken: req.csrfToken() }
  }

  @ApiOperation({
    summary: "Get current user",
    description: "Returns the currently authenticated user."
  })
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
