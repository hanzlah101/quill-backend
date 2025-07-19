import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException
} from "@nestjs/common"
import { Reflector } from "@nestjs/core"
import { EMAIL_VERIFIED_KEY } from "@/decorators/email-verification.decorator"
import { AuthenticatedRequest } from "@/types/express"

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request: AuthenticatedRequest = context.switchToHttp().getRequest()
    if (!request.user) {
      throw new UnauthorizedException("Unauthorized")
    }

    const checkEmailVerification = this.reflector.getAllAndOverride<boolean>(
      EMAIL_VERIFIED_KEY,
      [context.getHandler(), context.getClass()]
    )

    if (checkEmailVerification && !request.user.emailVerified) {
      throw new ForbiddenException("Email not verified")
    }

    return true
  }
}
