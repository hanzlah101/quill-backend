import { z } from "zod"
import { Logger } from "@nestjs/common"

const envSchema = z.object({
  PORT: z.coerce.number().default(8080),
  DATABASE_URL: z.url(),
  CLIENT_URL: z.url()
})

export function validateEnv(env: unknown) {
  const { data, error } = envSchema.safeParse(env)
  if (error) {
    Logger.error(z.prettifyError(error), "Invalid Env")
    process.exit(1)
  }
  return data
}

export type Env = z.infer<typeof envSchema>
