import { NestFactory } from "@nestjs/core"
import { apiReference } from "@scalar/nestjs-api-reference"
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger"
import { AppModule } from "@/modules/app.module"
import { EnvService } from "@/modules/env/env.service"
import { STATIC_ASSETS } from "@/utils/constants"
import * as cookieParser from "cookie-parser"
import {
  Logger,
  UnprocessableEntityException,
  ValidationPipe
} from "@nestjs/common"

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.setGlobalPrefix("/api")

  const configService = app.get(EnvService)

  app.enableCors({
    credentials: true,
    origin: configService.get("CLIENT_URL"),
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Content-Length"]
  })

  app.use(cookieParser())

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const messages = errors
          .map(({ constraints = [] }) => Object.values(constraints).join(", "))
          .filter(Boolean)
          .map((m) => `${m.charAt(0).toUpperCase()}${m.slice(1)}`)
          .join("\n")

        return new UnprocessableEntityException(messages)
      }
    })
  )

  const config = new DocumentBuilder()
    .setTitle("Quill API")
    .setDescription(
      "API documentation & testing interface for the Quill, a way to talk to your documents."
    )
    .setVersion("1.0.0")
    .build()

  const document = SwaggerModule.createDocument(app, config)
  app.use(
    "/api/docs",
    apiReference({
      content: document,
      title: config.info.title,
      description: config.info.description,
      theme: "kepler",
      favicon: STATIC_ASSETS.favicon,
      withCredentials: true,
      defaultHttpClient: {
        targetKey: "node",
        clientKey: "undici"
      }
    })
  )

  const port = configService.get("PORT")
  await app.listen(port)

  Logger.log(`Server is running on http://localhost:${port}`, "Bootstrap")
}
void bootstrap()
