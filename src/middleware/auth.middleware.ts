import { Injectable, NestMiddleware } from "@nestjs/common"
import { AuthService } from "@/modules/auth/auth.service"
import { NextFunction, Request, Response } from "express"
import { COOKIES } from "@/utils/constants"
import { cookieOpts } from "@/utils/options"

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const token = req.cookies[COOKIES.session]
    if (token) {
      const session = await this.authService.validateSession(token)

      if (session) {
        const { user, ...sessionData } = session
        req.user = user
        req.session = sessionData
        res.cookie(COOKIES.session, token, cookieOpts(session.expiresAt))
      } else {
        res.clearCookie(COOKIES.session)
        req.user = null
        req.session = null
      }
    }
    next()
  }
}
