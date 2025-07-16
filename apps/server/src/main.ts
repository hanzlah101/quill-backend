import { NestFactory } from "@nestjs/core"
import { Logger } from "@nestjs/common"
import { OpenApiGeneratorV31 } from "@asteasolutions/zod-to-openapi"
import { apiReference } from "@scalar/nestjs-api-reference"
import { AppModule } from "@/modules/app.module"
import { registry } from "@/utils/zod-openapi"

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.setGlobalPrefix("/api")

  const generator = new OpenApiGeneratorV31(registry.definitions)
  const document = generator.generateDocument({
    openapi: "3.1.0",
    info: {
      title: "Quill API Docs",
      version: "1.0.0"
    }
  })

  app.use("/api/docs", apiReference({ content: document }))

  const port = process.env.PORT ?? 8080
  await app.listen(port)

  Logger.log(`Server is running on port ${port}`, "Bootstrap")
}
void bootstrap()
