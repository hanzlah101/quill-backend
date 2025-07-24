import { Injectable } from "@nestjs/common"
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3"
import { EnvService } from "../env/env.service"
import { GetPresignedUrlDTO } from "./dto/get-presigned-url.dto"

@Injectable()
export class DocsService {
  private s3Client: S3Client

  constructor(private readonly env: EnvService) {
    this.s3Client = new S3Client({
      region: this.env.get("AWS_S3_REGION"),
      credentials: {
        accessKeyId: this.env.get("AWS_S3_ACCESS_KEY"),
        secretAccessKey: this.env.get("AWS_S3_SECRET_ACCESS_KEY")
      }
    })
  }

  async getPresignedUrl({ fileName, mimeType, size }: GetPresignedUrlDTO) {
    const key = `docs/${crypto.randomUUID()}-${fileName}`
    const command = new PutObjectCommand({
      Bucket: this.env.get("AWS_S3_BUCKET_NAME"),
      Key: key,
      ContentType: mimeType,
      ContentLength: size
    })

    const presignedUrl = await getSignedUrl(this.s3Client, command, {
      expiresIn: 3600
    })

    return { presignedUrl }
  }
}
