import { UserDTO } from "@/modules/auth/dto/user.dto"
import { Session as PrismaSession } from "@prisma/client"

declare global {
  namespace Express {
    export type User = UserDTO
    export type Session = PrismaSession
    interface Request {
      user: UserDTO | null
      session: PrismaSession | null
    }
  }
}

export type AuthenticatedRequest = Request & {
  user: UserDTO
  session: PrismaSession
}
