import { ERROR_CODES } from "@/utils/error-codes"
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable
} from "@nestjs/common"

@Injectable()
export class GuestGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    if (request.user) {
      throw new ForbiddenException(ERROR_CODES.ALREADY_LOGGED_IN.message)
    }

    return true
  }
}
