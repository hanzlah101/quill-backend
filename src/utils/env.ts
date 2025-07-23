import { z } from "zod"
import { Logger } from "@nestjs/common"

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production"]).default("development"),
  PORT: z.coerce.number().default(8080),
  DATABASE_URL: z.url(),
  CLIENT_URL: z.url(),
  SERVER_URL: z.url(),
  EMAIL_HOST: z.string().min(1),
  EMAIL_FROM: z.string().min(1),
  EMAIL_PASSWORD: z.string().min(1),
  AWS_S3_BUCKET_NAME: z.string().min(1),
  AWS_S3_ACCESS_KEY: z.string().min(1),
  AWS_S3_SECRET_ACCESS_KEY: z.string().min(1),
  AWS_S3_REGION: z.string().min(1),
  AWS_CLOUDFRONT_DISTRIBUTION_URL: z.url(),
  CSRF_SECRET: z.string().min(1),
  GITHUB_CLIENT_ID: z.string().min(1),
  GITHUB_CLIENT_SECRET: z.string().min(1),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1)
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
