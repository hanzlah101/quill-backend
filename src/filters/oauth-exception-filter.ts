import { Response } from "express"
import { EnvService } from "@/modules/env/env.service"
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  Injectable
} from "@nestjs/common"

@Catch()
@Injectable()
export class OAuthExceptionFilter implements ExceptionFilter {
  private static _provider: "google" | "github"

  constructor(private readonly env: EnvService) {}

  static provider(provider: "google" | "github"): typeof OAuthExceptionFilter {
    this._provider = provider
    return this
  }

  catch(_: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp()
    const res = ctx.getResponse<Response>()
    res
      .status(302)
      .redirect(
        `${this.env.get("CLIENT_URL")}/login?oauth_error=${OAuthExceptionFilter._provider}`
      )
  }
}
