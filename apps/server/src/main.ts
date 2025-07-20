import { NestFactory } from "@nestjs/core"
import { NestExpressApplication } from "@nestjs/platform-express"
import { AppModule } from "@/modules/app.module"
import { EnvService } from "@/modules/env/env.service"
import { setupDocs } from "./utils/setup-docs"
import { doubleCsrf } from "csrf-csrf"
import * as cookieParser from "cookie-parser"
import helmet from "helmet"
import { Logger, ValidationPipe } from "@nestjs/common"
import { corsOpts, csrfOpts, validationPipeOpts } from "./utils/options"
import { AuthMiddleware } from "@/middleware/auth.middleware"

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)
  app.setGlobalPrefix("/api")

  setupDocs(app)

  app.use(helmet())

  const env = app.get(EnvService)

  app.enableCors(corsOpts(env.get("CLIENT_URL")))

  app.use(cookieParser())
  app.set("trust proxy", true)

  const authMiddleware = app.get(AuthMiddleware)
  app.use((req, res, next) => authMiddleware.use(req, res, next))

  const { doubleCsrfProtection } = doubleCsrf(csrfOpts(env.get("CSRF_SECRET")))
  app.use(doubleCsrfProtection)

  app.useGlobalPipes(new ValidationPipe(validationPipeOpts))

  const port = env.get("PORT")
  await app.listen(port)

  Logger.log(`Server is running on http://localhost:${port}`, "Bootstrap")
}
void bootstrap()
