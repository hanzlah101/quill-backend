import { z } from "zod"
import { PipeTransform, BadRequestException } from "@nestjs/common"

export class ZodPipe implements PipeTransform {
  constructor(private schema: z.ZodType) {}

  transform(value: unknown) {
    const { data, error } = this.schema.safeParse(value)
    if (error) {
      throw new BadRequestException(z.prettifyError(error))
    }

    return data
  }
}
