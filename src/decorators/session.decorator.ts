import { createParamDecorator, ExecutionContext } from "@nestjs/common"
import { AuthenticatedRequest } from "@/types/express"

export const User = createParamDecorator(
  (_: unknown, ctx: ExecutionContext) => {
    const request: AuthenticatedRequest = ctx.switchToHttp().getRequest()
    return request.user
  }
)

export const Session = createParamDecorator(
  (_: unknown, ctx: ExecutionContext) => {
    const request: AuthenticatedRequest = ctx.switchToHttp().getRequest()
    return request.session
  }
)
