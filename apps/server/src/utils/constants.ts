const CLOUDFRONT_URL = process.env.AWS_CLOUDFRONT_DISTRIBUTION_URL

export const STATIC_ASSETS = {
  favicon: `${CLOUDFRONT_URL}/static/favicon.ico`,
  logo: `${CLOUDFRONT_URL}/static/logo.png`
}

export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  path: "/"
} as const

export const SESSION_COOKIE_NAME = "session_token"
