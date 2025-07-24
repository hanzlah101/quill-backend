import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { validateEnv } from "@/utils/env"
import { EnvModule } from "./env/env.module"
import { AuthModule } from "./auth/auth.module"
import { PrismaModule } from "./prisma/prisma.module"
import { MailerModule } from "@nestjs-modules/mailer"
import { EnvService } from "./env/env.service"
import { AuthMiddleware } from "@/middleware/auth.middleware"
import { DocsModule } from "./docs/docs.module"

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    EnvModule,
    PrismaModule,
    MailerModule.forRootAsync({
      inject: [EnvService],
      useFactory: (env: EnvService) => ({
        transport: {
          host: env.get("EMAIL_HOST"),
          auth: {
            user: env.get("EMAIL_FROM"),
            pass: env.get("EMAIL_PASSWORD")
          }
        }
      })
    }),
    AuthModule,
    DocsModule
  ],
  providers: [AuthMiddleware]
})
export class AppModule {}
