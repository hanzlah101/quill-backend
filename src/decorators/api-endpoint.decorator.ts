import { AuthGuard } from "@/guards/auth.guard"
import { GuestGuard } from "@/guards/guest.guard"
import { ERROR_CODES, ErrorCode } from "@/utils/error-codes"
import { CheckEmailVerification } from "./email-verification.decorator"
import { COOKIES } from "@/utils/constants"
import {
  applyDecorators,
  Delete,
  Get,
  HttpCode,
  Patch,
  Post,
  UseGuards
} from "@nestjs/common"
import {
  ApiOperation,
  ApiResponse,
  ApiResponseMetadata,
  ApiHeader
} from "@nestjs/swagger"

const METHOD = { Post, Get, Patch, Delete }
type Method = keyof typeof METHOD

const Guards = { GuestGuard, AuthGuard }

type ApiEndpointConfig = {
  summary: string
  description: string
  response: ApiResponseMetadata & { status: number }
  errors?: ErrorCode[]
  validation?: MethodDecorator | MethodDecorator[]
} & (
  | {
      guard?: "GuestGuard"
    }
  | {
      guard?: "AuthGuard"
      checkEmailVerification?: boolean
    }
)

export function ApiEndpoint(
  method: Method,
  path: string,
  config: ApiEndpointConfig
) {
  const decorators = [
    METHOD[method](path),
    ApiOperation({ summary: config.summary, description: config.description }),
    ApiResponse(config.response),
    HttpCode(config.response.status)
  ]

  if (method !== "Get") {
    decorators.push(
      ApiHeader({
        name: COOKIES.csrf,
        description: "CSRF token for state-changing operations",
        required: true,
        schema: { type: "string" }
      })
    )
  }

  const errors = new Set<ErrorCode>(["INTERNAL_SERVER_ERROR"])

  if (config.errors?.length) {
    config.errors.forEach((e) => errors.add(e))
  }

  if (config.validation) {
    errors.add("VALIDATION_FAILED")
    if (Array.isArray(config.validation)) {
      decorators.push(...config.validation)
    } else {
      decorators.push(config.validation)
    }
  }

  if (config.guard) {
    const guard = Guards[config.guard]
    decorators.push(UseGuards(guard))
    errors.add(
      config.guard === "AuthGuard" ? "UNAUTHORIZED" : "ALREADY_LOGGED_IN"
    )

    if (config.guard === "AuthGuard") {
      decorators.push(
        CheckEmailVerification(config.checkEmailVerification ?? true)
      )
      errors.add("EMAIL_NOT_VERIFIED")
    }
  }

  decorators.push(
    ...[...errors].map((status) => {
      const error = ERROR_CODES[status]
      return ApiResponse({
        status: error.status,
        description: error.message,
        schema: {
          type: "object",
          properties: {
            statusCode: { type: "number", example: error.status },
            error: { type: "string", example: error.error },
            message: { type: "string", example: error.message }
          }
        }
      })
    })
  )

  return applyDecorators(...decorators)
}
