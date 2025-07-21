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
import { ERROR_CODES } from "@/utils/error-codes"

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request: AuthenticatedRequest = context.switchToHttp().getRequest()
    if (!request.user || !request.session) {
      throw new UnauthorizedException(ERROR_CODES.UNAUTHORIZED.message)
    }

    const checkEmailVerification = this.reflector.getAllAndOverride<boolean>(
      EMAIL_VERIFIED_KEY,
      [context.getHandler(), context.getClass()]
    )

    if (checkEmailVerification === false || request.user.emailVerified) {
      return true
    }

    throw new ForbiddenException(ERROR_CODES.EMAIL_NOT_VERIFIED.message)
  }
}
