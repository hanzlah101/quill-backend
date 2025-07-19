import { BadRequestException, Injectable } from "@nestjs/common"
import { hash, verify } from "@node-rs/argon2"
import { SignUpDTO } from "./dto/sign-up.dto"
import { PrismaService } from "@/modules/prisma/prisma.service"
import { handleUniqueException } from "@/utils/helpers"
import { LoginDTO } from "./dto/login.dto"
import { customAlphabet } from "nanoid"
import { EnvService } from "../env/env.service"
import { MailerService } from "@nestjs-modules/mailer"
import { verificationEmail } from "@/utils/email-templates"
import { sha256 } from "@oslojs/crypto/sha2"
import { COOKIE_OPTIONS, SESSION_COOKIE_NAME } from "@/utils/constants"
import type { Response, Request } from "express"
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase
} from "@oslojs/encoding"

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly mailer: MailerService,
    private readonly env: EnvService
  ) {}

  async signUp({ name, email, password }: SignUpDTO) {
    const passwordHash = await hash(password, this.passwordOpts)

    const user = await this.prisma.user
      .create({
        data: { name, email, passwordHash },
        omit: { passwordHash: true }
      })
      .catch(handleUniqueException("User already exists"))

    await this.sendVerificationEmail(email, false)

    return user
  }

  async login({ email, password }: LoginDTO) {
    const user = await this.prisma.user.findUnique({
      where: { email }
    })

    if (!user) {
      await hash(password, this.passwordOpts) // Prevent timing attacks
      throw new BadRequestException("Invalid credentials")
    }

    const { passwordHash, ...userData } = user

    if (!passwordHash) {
      throw new BadRequestException(
        "This account is linked to a social account."
      )
    }

    const isPasswordValid = await verify(
      passwordHash,
      password,
      this.passwordOpts
    )

    if (!isPasswordValid) {
      throw new BadRequestException("Invalid credentials")
    }

    if (!userData.emailVerified) {
      // await this.sendVerificationEmail(userData.email)
    }

    return userData
  }

  async resendVerificationEmail(email: string) {
    await this.sendVerificationEmail(email)
  }

  async me(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      omit: { passwordHash: true }
    })
  }

  async logout(sessionId: string) {
    await this.prisma.session.delete({ where: { id: sessionId } })
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

    res.cookie(SESSION_COOKIE_NAME, token, {
      ...COOKIE_OPTIONS,
      expires: session.expiresAt
    })

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

    if (!session) {
      return { user: null, session: null }
    }

    if (Date.now() >= session.expiresAt.getTime()) {
      await this.prisma.session.delete({
        where: { id: session.id }
      })
      return { user: null, session: null }
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

    return { user: session.user, session }
  }

  private getClientIP(req: Request) {
    const xForwardedFor = req.headers["x-forwarded-for"]
    if (typeof xForwardedFor === "string") {
      const ips = xForwardedFor.split(",").map((ip) => ip.trim())
      return ips[0] // Return first (client) IP in chain
    }
    return req.ip || null
  }

  private async sendVerificationEmail(identifier: string, cleanup = true) {
    if (cleanup) {
      await this.prisma.emailVerificationToken.deleteMany({
        where: { identifier }
      })
    }

    const token = customAlphabet("1234567890", 6)()
    await this.prisma.emailVerificationToken.create({
      data: {
        token,
        identifier,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
      }
    })

    await this.mailer.sendMail({
      to: identifier,
      subject: "Quill Verification Code",
      ...verificationEmail(token)
    })
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
