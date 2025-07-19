import { ConflictException } from "@nestjs/common"
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library"

export function handleUniqueException(message: string) {
  return (err: unknown) => {
    if (err instanceof PrismaClientKnownRequestError && err.code === "P2002") {
      throw new ConflictException(message)
    }
    throw err
  }
}
