import { ApiProperty } from "@nestjs/swagger"
import { IsNumber, IsString, Min, MinLength, Equals } from "class-validator"

export class GetPresignedUrlDTO {
  @ApiProperty({
    example: "example.pdf",
    description: "The name of the file for which to generate a presigned URL",
    minLength: 1
  })
  @IsString()
  @MinLength(1)
  fileName: string

  @ApiProperty({
    example: "application/pdf",
    description: "The MIME type of the file being uploaded"
  })
  @IsString()
  @Equals("application/pdf", {
    message: "MIME type must be application/pdf"
  })
  mimeType: string

  @ApiProperty({
    example: 1024,
    description: "The size of the file in bytes",
    minimum: 1
  })
  @IsNumber()
  @Min(1)
  size: number
}

export class GetPresignedUrlResDTO {
  @ApiProperty({
    example:
      "https://example-bucket.s3.amazonaws.com/docs/12345-example.pdf?AWSAccessKeyId=AKIA...",
    description: "The presigned URL for uploading the file"
  })
  @IsString()
  presignedUrl: string
}
