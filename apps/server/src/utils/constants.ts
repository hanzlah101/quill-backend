const CLOUDFRONT_URL = process.env.AWS_CLOUDFRONT_DISTRIBUTION_URL

export const STATIC_ASSETS = {
  favicon: `${CLOUDFRONT_URL}/static/favicon.ico`,
  logo: `${CLOUDFRONT_URL}/static/logo.png`
}

export const COOKIES = {
  session: "session_token",
  csrf: "x_csrf_token",
  githubState: "github_oauth_state",
  redirectUrl: "redirect_url",
  googleState: "google_oauth_state",
  googleCodeVerifier: "google_oauth_code_verifier"
} as const

export const CSRF_HEADER = "x-csrf-token"
