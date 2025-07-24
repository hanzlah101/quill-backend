import {
  BadRequestException,
  ConflictException,
  Injectable,
  BadGatewayException,
  UnprocessableEntityException
} from "@nestjs/common"
import { ERROR_CODES } from "@/utils/error-codes"
import { hash, verify } from "@node-rs/argon2"
import { SignUpDTO } from "./dto/sign-up.dto"
import { PrismaService } from "@/modules/prisma/prisma.service"
import { handleUniqueException } from "@/utils/helpers"
import { LoginDTO } from "./dto/login.dto"
import { MailerService } from "@nestjs-modules/mailer"
import { resetPasswordEmail, verificationEmail } from "@/utils/email-templates"
import { UserDTO } from "./dto/user.dto"
import { sha256 } from "@oslojs/crypto/sha2"
import { COOKIES } from "@/utils/constants"
import { ChangePasswordDTO } from "./dto/change-password.dto"
import { cookieOpts } from "@/utils/options"
import { EnvService } from "../env/env.service"
import {
  decodeIdToken,
  generateCodeVerifier,
  generateState,
  GitHub,
  Google
} from "arctic"
import type { Response, Request } from "express"
import { GithubCallbackDTO, GithubLoginDTO } from "./dto/github-login.dto"
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase
} from "@oslojs/encoding"
import { GoogleCallbackDTO, GoogleLoginDTO } from "./dto/google-login.dto"

@Injectable()
export class AuthService {
  private github: GitHub
  private google: Google

  constructor(
    private readonly prisma: PrismaService,
    private readonly mailer: MailerService,
    private readonly env: EnvService
  ) {
    this.github = new GitHub(
      this.env.get("GITHUB_CLIENT_ID"),
      this.env.get("GITHUB_CLIENT_SECRET"),
      this.env.get("SERVER_URL") + "/api/auth/github/callback"
    )

    this.google = new Google(
      this.env.get("GOOGLE_CLIENT_ID"),
      this.env.get("GOOGLE_CLIENT_SECRET"),
      this.env.get("SERVER_URL") + "/api/auth/google/callback"
    )
  }

  async signUp({ name, email, password }: SignUpDTO) {
    const passwordHash = await hash(password, this.passwordOpts)

    const user = await this.prisma.user
      .create({
        data: { name, email, passwordHash },
        omit: { passwordHash: true }
      })
      .catch(handleUniqueException(ERROR_CODES.USER_ALREADY_EXISTS.message))

    await this.sendVerificationEmail(user.id, user.email)

    return user
  }

  async verifyEmail(user: UserDTO, token: string) {
    if (user.emailVerified) {
      throw new BadRequestException(ERROR_CODES.EMAIL_ALREADY_VERIFIED.message)
    }

    const verificationToken =
      await this.prisma.emailVerificationToken.findUnique({
        where: { userId_token: { userId: user.id, token } }
      })

    if (!verificationToken) {
      throw new BadRequestException(
        ERROR_CODES.INVALID_VERIFICATION_CODE.message
      )
    }

    if (verificationToken.expiresAt.getTime() < new Date().getTime()) {
      await this.prisma.emailVerificationToken.delete({
        where: { userId_token: { userId: verificationToken.userId, token } }
      })
      throw new BadRequestException(
        ERROR_CODES.INVALID_VERIFICATION_CODE.message
      )
    }

    await this.prisma.user.update({
      where: { id: verificationToken.userId },
      data: { emailVerified: true }
    })

    await this.prisma.emailVerificationToken.delete({
      where: { userId_token: { userId: verificationToken.userId, token } }
    })
  }

  async resendVerification(user: UserDTO) {
    if (user.emailVerified) {
      throw new BadRequestException(ERROR_CODES.EMAIL_ALREADY_VERIFIED.message)
    }

    await this.sendVerificationEmail(user.id, user.email)
  }

  async login({ email, password }: LoginDTO) {
    const user = await this.prisma.user.findUnique({
      where: { email }
    })

    if (!user) {
      await hash(password, this.passwordOpts) // Prevent timing attacks
      throw new BadRequestException(ERROR_CODES.INVALID_CREDENTIALS.message)
    }

    const { passwordHash, ...userData } = user

    if (!passwordHash) {
      throw new BadRequestException(
        ERROR_CODES.ACCOUNT_LINKED_TO_SOCIAL.message
      )
    }

    const isPasswordValid = await verify(
      passwordHash,
      password,
      this.passwordOpts
    )

    if (!isPasswordValid) {
      throw new BadRequestException(ERROR_CODES.INVALID_CREDENTIALS.message)
    }

    if (!userData.emailVerified) {
      await this.sendVerificationEmail(userData.id, userData.email)
    }

    return userData
  }

  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({
      where: { email }
    })

    if (!user) {
      throw new BadRequestException(ERROR_CODES.EMAIL_NOT_FOUND.message)
    }

    const token = this.generateSessionToken()
    const id = encodeHexLowerCase(sha256(new TextEncoder().encode(token)))

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    await this.prisma.passwordResetSession.upsert({
      create: {
        id,
        userId: user.id,
        expiresAt
      },
      update: {
        id,
        expiresAt
      },
      where: { userId: user.id }
    })

    await this.mailer
      .sendMail({
        to: email,
        subject: "Quill Password Reset Request",
        ...resetPasswordEmail(token)
      })
      .catch(() => {
        throw new BadGatewayException(ERROR_CODES.EMAIL_SEND_FAILED.message)
      })
  }

  async resetPassword(token: string, newPassword: string) {
    const id = encodeHexLowerCase(sha256(new TextEncoder().encode(token)))

    const resetSession = await this.prisma.passwordResetSession.findUnique({
      where: { id }
    })

    if (!resetSession) {
      throw new BadRequestException(ERROR_CODES.INVALID_RESET_TOKEN.message)
    }

    if (resetSession.expiresAt.getTime() < Date.now()) {
      await this.prisma.passwordResetSession.delete({
        where: { id: resetSession.id }
      })
      throw new BadRequestException(ERROR_CODES.INVALID_RESET_TOKEN.message)
    }

    const passwordHash = await hash(newPassword, this.passwordOpts)

    await this.prisma.user.update({
      where: { id: resetSession.userId },
      data: { passwordHash }
    })

    await this.prisma.passwordResetSession.delete({
      where: { id: resetSession.id }
    })
  }

  async changePassword(
    userId: string,
    { currentPassword, newPassword }: ChangePasswordDTO
  ) {
    if (newPassword === currentPassword) {
      throw new UnprocessableEntityException(
        ERROR_CODES.SAME_NEW_PASSWORD.message
      )
    }

    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
      select: { passwordHash: true }
    })

    if (!user.passwordHash) {
      throw new ConflictException(ERROR_CODES.ACCOUNT_LINKED_TO_SOCIAL.message)
    }

    const isCurrentPasswordValid = await verify(
      user.passwordHash,
      currentPassword,
      this.passwordOpts
    )

    if (!isCurrentPasswordValid) {
      throw new BadRequestException(
        ERROR_CODES.INCORRECT_CURRENT_PASSWORD.message
      )
    }

    const newPasswordHash = await hash(newPassword, this.passwordOpts)

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newPasswordHash }
    })

    await this.prisma.session.deleteMany({
      where: { userId }
    })
  }

  githubLogin(res: Response, { redirect_url }: GithubLoginDTO) {
    const state = generateState()
    const url = this.github.createAuthorizationURL(state, [
      "read:user",
      "user:email"
    ])
    const expires = new Date(Date.now() + 20 * 60 * 1000) // 20 minutes
    res.cookie(COOKIES.redirectUrl, redirect_url, cookieOpts(expires))
    res.cookie(COOKIES.githubState, state, cookieOpts(expires))
    return { url: url.toString() }
  }

  async githubCallback(
    req: Request,
    res: Response,
    { state, code }: GithubCallbackDTO
  ) {
    const storedState = req.cookies[COOKIES.githubState]
    if (!storedState || storedState !== state) {
      throw new BadRequestException()
    }

    const tokens = await this.github.validateAuthorizationCode(code)
    const { access_token, scope } = tokens.data as {
      access_token: string
      scope: string
    }
    const githubUserResponse = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    })

    if (!githubUserResponse.ok) {
      throw new BadRequestException()
    }

    const githubUser = (await githubUserResponse.json()) as {
      id: number
      login: string
      email: string | null
      name: string | null
      avatar_url: string
    }

    const emailsResponse = await fetch("https://api.github.com/user/emails", {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    })

    if (!emailsResponse.ok) {
      throw new BadRequestException()
    }

    const emails = (await emailsResponse.json()) as {
      email: string
      primary: boolean
      verified: boolean
    }[]

    const githubEmail = emails.find((e) => e.primary) ?? emails[0] ?? null
    if (!githubEmail) {
      throw new BadRequestException()
    }

    const user = await this.createOAuthAccount({
      providerId: String(githubUser.id),
      name: githubUser.name ?? githubUser.login,
      email: githubEmail.email,
      provider: "github",
      image: githubUser.avatar_url,
      accessToken: access_token,
      scope: scope,
      emailVerified: githubEmail.verified
    })

    await this.createSession(user.id, req, res)

    const redirectUrl = new URL(
      req.cookies[COOKIES.redirectUrl] ?? "",
      this.env.get("CLIENT_URL")
    )

    if (user.isNew) {
      redirectUrl.searchParams.set("new_user", "true")
    }

    res.clearCookie(COOKIES.githubState)
    res.clearCookie(COOKIES.redirectUrl)
    res.redirect(redirectUrl.toString())
  }

  googleLogin(res: Response, { redirect_url }: GoogleLoginDTO) {
    const state = generateState()
    const codeVerifier = generateCodeVerifier()
    const url = this.google.createAuthorizationURL(state, codeVerifier, [
      "openid",
      "profile",
      "email"
    ])

    const expires = new Date(Date.now() + 20 * 60 * 1000) // 20 minutes
    res.cookie(COOKIES.googleState, state, cookieOpts(expires))
    res.cookie(COOKIES.googleCodeVerifier, codeVerifier, cookieOpts(expires))
    res.cookie(COOKIES.redirectUrl, redirect_url, cookieOpts(expires))
    return { url: url.toString() }
  }

  async googleCallback(
    req: Request,
    res: Response,
    { state, code }: GoogleCallbackDTO
  ) {
    const storedState = req.cookies[COOKIES.googleState]
    const codeVerifier = req.cookies[COOKIES.googleCodeVerifier]

    if (!storedState || storedState !== state || !codeVerifier) {
      throw new BadRequestException()
    }

    const tokens = await this.google.validateAuthorizationCode(
      code,
      codeVerifier
    )

    const { access_token, id_token } = tokens.data as {
      access_token: string
      id_token: string
    }

    const googleUser = decodeIdToken(id_token) as {
      sub: string
      email: string
      scope: string
      name: string | null
      picture: string | null
      email_verified: boolean
    }

    if (!googleUser.email) {
      throw new BadRequestException()
    }

    const user = await this.createOAuthAccount({
      providerId: googleUser.sub,
      name: googleUser.name ?? googleUser.email.split("@")[0],
      email: googleUser.email,
      provider: "google",
      image: googleUser.picture,
      accessToken: access_token,
      scope: googleUser.scope,
      emailVerified: googleUser.email_verified,
      accessTokenExpiresAt: tokens.accessTokenExpiresAt(),
      refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : null
    })

    await this.createSession(user.id, req, res)

    const redirectUrl = new URL(
      req.cookies[COOKIES.redirectUrl] ?? "",
      this.env.get("CLIENT_URL")
    )

    if (user.isNew) {
      redirectUrl.searchParams.set("new_user", "true")
    }

    res.clearCookie(COOKIES.googleState)
    res.clearCookie(COOKIES.googleCodeVerifier)
    res.clearCookie(COOKIES.redirectUrl)
    res.redirect(redirectUrl.toString())
  }

  async logout(sessionId: string) {
    await this.prisma.session.delete({ where: { id: sessionId } })
  }

  async me(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      omit: { passwordHash: true }
    })
  }

  async createSession(userId: string, req: Request, res: Response) {
    const token = this.generateSessionToken()
    const sessionId = encodeHexLowerCase(
      sha256(new TextEncoder().encode(token))
    )

    const session = await this.prisma.session.create({
      data: {
        id: sessionId,
        userId,
        ipAddress: this.getClientIP(req),
        userAgent: req.headers["user-agent"] ?? null,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
      }
    })

    res.cookie(COOKIES.session, token, cookieOpts(session.expiresAt))

    return session
  }

  async validateSession(token: string) {
    const sessionId = encodeHexLowerCase(
      sha256(new TextEncoder().encode(token))
    )
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: { omit: { passwordHash: true } } }
    })

    if (!session) return null

    if (session.expiresAt.getTime() < Date.now()) {
      await this.prisma.session.delete({
        where: { id: session.id }
      })
      return null
    }

    const fifteenDaysFromNow = Date.now() + 1000 * 60 * 60 * 24 * 15
    if (session.expiresAt.getTime() < fifteenDaysFromNow) {
      const newExpiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30) // 30 days
      await this.prisma.session.update({
        where: { id: session.id },
        data: { expiresAt: newExpiresAt }
      })
      session.expiresAt = newExpiresAt
    }

    return session
  }

  private async createOAuthAccount({
    name,
    email,
    image,
    provider,
    emailVerified,
    ...oauthParams
  }: {
    providerId: string
    name: string
    email: string
    provider: "github" | "google"
    image: string | null
    accessToken: string
    scope: string
    emailVerified: boolean
    accessTokenExpiresAt?: Date | null
    refreshToken?: string | null
  }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email }
    })

    if (existingUser) {
      const existingOAuthAccount = await this.prisma.oAuthAccount.findUnique({
        where: {
          userId_provider: { userId: existingUser.id, provider }
        }
      })

      if (!existingOAuthAccount) {
        await this.prisma.oAuthAccount.create({
          data: {
            provider,
            userId: existingUser.id,
            ...oauthParams
          }
        })
      }

      return { ...existingUser, isNew: false }
    } else {
      const newUser = await this.prisma.user.create({
        data: { email, name, image, emailVerified }
      })

      await this.prisma.oAuthAccount.create({
        data: {
          provider,
          userId: newUser.id,
          ...oauthParams
        }
      })

      return { ...newUser, isNew: true }
    }
  }

  private getClientIP(req: Request) {
    const xForwardedFor = req.headers["x-forwarded-for"]
    if (typeof xForwardedFor === "string") {
      const ips = xForwardedFor.split(",").map((ip) => ip.trim())
      return ips[0] // Return first (client) IP in chain
    }
    return req.ip || null
  }

  private async sendVerificationEmail(userId: string, email: string) {
    try {
      const token = this.generateRandomOTP()

      const expiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
      await this.prisma.emailVerificationToken.upsert({
        create: { token, userId, expiresAt },
        update: { token, expiresAt },
        where: { userId }
      })

      await this.mailer.sendMail({
        to: email,
        subject: "Quill Verification Code",
        ...verificationEmail(token)
      })
    } catch {
      throw new BadGatewayException(ERROR_CODES.EMAIL_SEND_FAILED.message)
    }
  }

  private generateRandomOTP() {
    const array = new Uint32Array(1)
    crypto.getRandomValues(array)
    return (array[0] % 1000000).toString().padStart(6, "0")
  }

  private generateSessionToken() {
    const tokenBytes = new Uint8Array(20)
    crypto.getRandomValues(tokenBytes)
    const token = encodeBase32LowerCaseNoPadding(tokenBytes).toLowerCase()
    return token
  }

  private readonly passwordOpts = {
    memoryCost: 19456,
    timeCost: 2,
    outputLen: 32,
    parallelism: 1
  }
}
