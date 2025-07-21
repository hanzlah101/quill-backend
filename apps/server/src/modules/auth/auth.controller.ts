import {
  Body,
  Controller,
  InternalServerErrorException,
  Param,
  Req,
  Res
} from "@nestjs/common"
import { AuthService } from "./auth.service"
import { ApiBody, ApiParam, ApiTags } from "@nestjs/swagger"
import { SignUpDTO } from "./dto/sign-up.dto"
import { UserDTO } from "./dto/user.dto"
import { LoginDTO } from "./dto/login.dto"
import { Request, Response } from "express"
import { Session, User } from "@/decorators/session.decorator"
import { COOKIES } from "@/utils/constants"
import { VerifyEmailDTO } from "./dto/verify-email.dto"
import { ChangePasswordDTO } from "./dto/change-password.dto"
import { CSRFTokenDTO } from "./dto/csrf-token.dto"
import { ApiEndpoint } from "@/decorators/api-endpoint.decorator"
import {
  ResetPasswordDTO,
  ResetPasswordRequestDTO
} from "./dto/reset-password.dto"

@ApiTags("Auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiEndpoint("Post", "sign-up", {
    summary: "Sign up a new user",
    description: "Creates a new user account and sends a verification email.",
    guard: "GuestGuard",
    errors: ["USER_ALREADY_EXISTS", "ALREADY_LOGGED_IN"],
    validation: ApiBody({ type: SignUpDTO }),
    response: {
      status: 201,
      description: "User successfully created",
      type: UserDTO
    }
  })
  async signUp(
    @Body() body: SignUpDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const user = await this.authService.signUp(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @ApiEndpoint("Post", "verify-email", {
    summary: "Verify email",
    description: "Verifies the user's email using a verification code.",
    guard: "AuthGuard",
    checkEmailVerification: false,
    validation: ApiBody({ type: VerifyEmailDTO }),
    errors: ["INVALID_VERIFICATION_CODE", "EMAIL_ALREADY_VERIFIED"],
    response: {
      status: 204,
      description: "Email verified successfully"
    }
  })
  async verifyEmail(@User() user: UserDTO, @Body() body: VerifyEmailDTO) {
    await this.authService.verifyEmail(user, body.code)
  }

  @ApiEndpoint("Post", "resend-verification", {
    summary: "Resend verification email",
    description: "Sends a new verification email to the user.",
    guard: "AuthGuard",
    checkEmailVerification: false,
    errors: ["EMAIL_ALREADY_VERIFIED"],
    response: {
      status: 204,
      description: "Verification email sent successfully"
    }
  })
  async resendVerificationEmail(@User() user: UserDTO) {
    await this.authService.resendVerification(user)
  }

  @ApiEndpoint("Post", "login", {
    summary: "Login user",
    description: "Logs in a user and creates a session.",
    guard: "GuestGuard",
    validation: ApiBody({ type: LoginDTO }),
    errors: ["ALREADY_LOGGED_IN", "INVALID_CREDENTIALS"],
    response: {
      status: 200,
      description: "User successfully logged in",
      type: UserDTO
    }
  })
  async login(
    @Body() body: LoginDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const user = await this.authService.login(body)
    await this.authService.createSession(user.id, req, res)
    return user
  }

  @ApiEndpoint("Post", "reset-password", {
    summary: "Request password reset",
    description: "Sends a password reset email to the user.",
    guard: "GuestGuard",
    validation: ApiBody({ type: ResetPasswordRequestDTO }),
    response: {
      status: 204,
      description: "Password reset request successful"
    }
  })
  async requestPasswordReset(@Body() body: ResetPasswordRequestDTO) {
    await this.authService.requestPasswordReset(body.email)
  }

  @ApiEndpoint("Patch", "reset-password/:token", {
    summary: "Reset password",
    description: "Resets the user's password using a reset token.",
    guard: "GuestGuard",
    errors: ["INVALID_RESET_TOKEN"],
    validation: [
      ApiBody({ type: ResetPasswordDTO }),
      ApiParam({
        name: "token",
        description: "The password reset token",
        example: "abc123xyz456"
      })
    ],
    response: {
      status: 204,
      description: "Password reset successful"
    }
  })
  async resetPassword(
    @Param("token") token: string,
    @Body() body: ResetPasswordDTO
  ) {
    await this.authService.resetPassword(token, body.newPassword)
  }

  @ApiEndpoint("Patch", "change-password", {
    summary: "Change password",
    description:
      "Changes the user's password after verifying the current password.",
    guard: "AuthGuard",
    validation: ApiBody({ type: ChangePasswordDTO }),
    errors: [
      "VALIDATION_FAILED",
      "ACCOUNT_LINKED_TO_SOCIAL",
      "INCORRECT_CURRENT_PASSWORD"
    ],
    response: {
      status: 204,
      description: "Password changed successfully"
    }
  })
  async changePassword(
    @User() user: Express.User,
    @Body() body: ChangePasswordDTO,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    await this.authService.changePassword(user.id, body)
    await this.authService.createSession(user.id, req, res)
  }

  @ApiEndpoint("Delete", "logout", {
    summary: "Logout user",
    description: "Logs out the user and clears the session.",
    guard: "AuthGuard",
    response: {
      status: 204,
      description: "User successfully logged out"
    }
  })
  async logout(
    @Session() session: Express.Session,
    @Res({ passthrough: true }) res: Response
  ) {
    await this.authService.logout(session.id)
    res.clearCookie(COOKIES.session)
    res.clearCookie(COOKIES.csrf)
  }

  @ApiEndpoint("Get", "csrf-token", {
    summary: "Get CSRF token",
    description: "Returns the CSRF token for the current session.",
    response: {
      status: 200,
      description: "Returns the CSRF token",
      type: CSRFTokenDTO
    }
  })
  getCsrfToken(@Req() req: Request) {
    if (!req.csrfToken) throw new InternalServerErrorException()
    return { csrfToken: req.csrfToken() }
  }

  @ApiEndpoint("Get", "me", {
    summary: "Get current user",
    description: "Returns the currently authenticated user.",
    guard: "AuthGuard",
    checkEmailVerification: false,
    response: {
      status: 200,
      description: "Returns the current user",
      type: UserDTO
    }
  })
  me(@User() user: Express.User) {
    return user
  }
}
