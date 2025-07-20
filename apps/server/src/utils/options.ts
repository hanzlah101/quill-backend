import { CookieOptions } from "express"
import { DoubleCsrfConfigOptions } from "csrf-csrf"
import { CorsOptions } from "@nestjs/common/interfaces/external/cors-options.interface"
import {
  UnprocessableEntityException,
  ValidationPipeOptions
} from "@nestjs/common"

export function cookieOpts(opts: CookieOptions): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    ...opts
  }
}

export function corsOpts(origin: CorsOptions["origin"]): CorsOptions {
  return {
    origin,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
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
    getSecret: () => secret,
    getSessionIdentifier: (req) => req.session?.id ?? "",
    cookieOptions: cookieOpts({ maxAge: 24 * 60 * 60 * 1000 })
  }
}
