import { STATIC_ASSETS } from "./constants"
import { NestExpressApplication } from "@nestjs/platform-express"
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger"
import { apiReference } from "@scalar/nestjs-api-reference"

export function setupDocs(app: NestExpressApplication) {
  const config = new DocumentBuilder()
    .setTitle("Quill API")
    .setDescription("API docs for Quill, a way to talk to your documents.")
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
      defaultHttpClient: {
        targetKey: "node",
        clientKey: "fetch"
      }
    })
  )
}
