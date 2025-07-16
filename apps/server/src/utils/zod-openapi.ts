import { z } from "zod"
import {
  OpenAPIRegistry,
  extendZodWithOpenApi
} from "@asteasolutions/zod-to-openapi"

extendZodWithOpenApi(z)
const registry = new OpenAPIRegistry()

export function defineZodSchema(schema: z.ZodType, name: `${string}Dto`) {
  registry.register(name, schema)
}

export { z, registry }
