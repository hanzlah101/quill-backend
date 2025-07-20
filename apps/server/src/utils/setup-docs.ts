import { COOKIES, STATIC_ASSETS } from "./constants"
import { NestExpressApplication } from "@nestjs/platform-express"
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger"
import { apiReference } from "@scalar/nestjs-api-reference"

export function setupDocs(app: NestExpressApplication) {
  const config = new DocumentBuilder()
    .setTitle("Quill API")
    .setDescription(
      "API documentation & testing interface for the Quill, a way to talk to your documents."
    )
    .addGlobalParameters({
      name: COOKIES.csrf,
      in: "header",
      schema: { type: "string" },
      description: "CSRF token for state-changing operations"
    })
    .setVersion("1.0.0")
    .build()

  const document = SwaggerModule.createDocument(app, config)

  Object.values(document.paths).forEach((path) => {
    Object.entries(path).forEach(([method, operation]) => {
      if (["get", "head", "options"].includes(method)) {
        operation.parameters = operation.parameters?.filter(
          ({ name }: { name: string }) => name !== COOKIES.csrf
        )
      }
    })
  })

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
