import { NestFactory } from "@nestjs/core"
import { Logger } from "@nestjs/common"
import { apiReference } from "@scalar/nestjs-api-reference"
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger"
import { AppModule } from "@/modules/app.module"
import { EnvService } from "@/modules/env/env.service"

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

  const config = new DocumentBuilder()
    .setTitle("Quill API")
    .setDescription("API documentation & testing interface for the Quill.")
    .setVersion("1.0.0")
    .build()

  const document = SwaggerModule.createDocument(app, config)

  app.use("/api", apiReference({ content: document, theme: "none" }))

  const port = configService.get("PORT")
  await app.listen(port)

  Logger.log(`Server is running on http://localhost:${port}`, "Bootstrap")
}
void bootstrap()
