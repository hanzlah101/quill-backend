import { Injectable, NestMiddleware } from "@nestjs/common"
import { AuthService } from "@/modules/auth/auth.service"
import { NextFunction, Request, Response } from "express"
import { SESSION_COOKIE_NAME } from "@/utils/constants"
import { cookieOpts } from "@/utils/options"

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const token = req.cookies[SESSION_COOKIE_NAME]
    if (token) {
      const { user, session } = await this.authService.validateSession(token)

      if (user && session) {
        req.user = user
        req.session = session
        res.cookie(
          SESSION_COOKIE_NAME,
          token,
          cookieOpts({ expires: session.expiresAt })
        )
      } else {
        res.clearCookie(SESSION_COOKIE_NAME)
        req.user = null
        req.session = null
      }
    }
    next()
  }
}
