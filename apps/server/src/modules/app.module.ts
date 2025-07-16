import { Module } from "@nestjs/common"
import { ConfigModule } from "@nestjs/config"
import { validateEnv } from "@/utils/env"
import { EnvModule } from "./env/env.module"

@Module({
  imports: [
    EnvModule,
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv })
  ]
})
export class AppModule {}
