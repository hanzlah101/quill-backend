import { CookieOptions } from "express"
import { DoubleCsrfConfigOptions } from "csrf-csrf"
import { CorsOptions } from "@nestjs/common/interfaces/external/cors-options.interface"
import { COOKIES } from "./constants"
import {
  UnprocessableEntityException,
  ValidationPipeOptions
} from "@nestjs/common"

export function cookieOpts(expiresAt: Date | number): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires:
      typeof expiresAt === "number"
        ? new Date(Date.now() + expiresAt)
        : expiresAt
  }
}

export function corsOpts(origin: CorsOptions["origin"]): CorsOptions {
  return {
    origin,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "x-csrf-token"],
    exposedHeaders: ["Content-Length"]
  }
}

export const validationPipeOpts: ValidationPipeOptions = {
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  exceptionFactory: (errors) => {
    const message = errors
      .map(({ constraints = [] }) => Object.values(constraints).join(", "))
      .filter(Boolean)
      .map((m) => `${m.charAt(0).toUpperCase()}${m.slice(1)}`)
      .join("\n")

    return new UnprocessableEntityException(message)
  }
}

export function csrfOpts(secret: string): DoubleCsrfConfigOptions {
  return {
    size: 32,
    cookieName: COOKIES.csrf,
    getSecret: () => secret,
    skipCsrfProtection: (req) => !req.session,
    getSessionIdentifier: (req) => req.session?.id as string,
    getCsrfTokenFromRequest: (req) => req.headers[COOKIES.csrf],
    cookieOptions: cookieOpts(60 * 60 * 1000) // 1 hour
  }
}
