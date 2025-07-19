import { STATIC_ASSETS } from "@/utils/constants"

export function verificationEmail(token: string) {
  const html = `
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html dir="ltr" lang="en">
      <head>
        <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
        <meta name="x-apple-disable-message-reformatting" />
      </head>
      <body
        style='background-color:white;padding-top:2.5rem;padding-bottom:2.5rem;font-family:ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";color:#111827'>
        <table
          align="center"
          width="100%"
          border="0"
          cellpadding="0"
          cellspacing="0"
          role="presentation"
          style="margin-left:auto;margin-right:auto;max-width:36rem;border-radius:1rem;background-color:#f4f4f5;padding-left:2rem;padding-right:2rem;padding-top:4rem;padding-bottom:4rem">
          <tbody>
            <tr style="width:100%">
              <td>
                <table
                  align="center"
                  width="100%"
                  border="0"
                  cellpadding="0"
                  cellspacing="0"
                  role="presentation"
                  style="width:2rem;height:2rem;flex-shrink:0;text-align:center">
                  <tbody>
                    <tr>
                      <td>
                        <img
                          alt="Quill"
                          src=${STATIC_ASSETS.logo}
                          style="margin-left:auto;margin-right:auto;margin-bottom:1rem;width:2.75rem;height:2.75rem;flex-shrink:0;object-fit:contain;display:block;outline:none;border:none;text-decoration:none" />
                      </td>
                    </tr>
                  </tbody>
                </table>
                <h1
                  style="text-align:center;font-size:1.5rem;line-height:2rem;font-weight:600;color:#111827">
                  Verify your email
                </h1>
                <p
                  style="margin-left:auto;margin-right:auto;max-width:24rem;text-align:center;font-size:0.875rem;line-height:1.25rem;margin-top:16px;margin-bottom:16px;color:#3f3f46">
                  Enter the following code in the app to verify your email. This code is valid for 15 minutes.
                </p>
                <div
                  style="text-align:center;font-size:2rem;font-weight:700;margin-top:1.5rem;margin-bottom:2rem;letter-spacing:0.2rem;color:#7c3aed">
                  ${token}
                </div>
                <p
                  style="text-align:center;font-size:0.75rem;line-height:1rem;color:#a1a1aa;margin-top:16px;margin-bottom:16px">
                  © 2025 Quill. All rights reserved.
                </p>
              </td>
            </tr>
          </tbody>
        </table>
      </body>
    </html>
  `

  return {
    html,
    text: `Your verification code is ${token}. This code is valid for 15 minutes.`
  }
}

export function resetPasswordEmail(token: string) {
  const resetUrl = `${process.env.CLIENT_URL}/reset-password/${token}`

  const html = `
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html dir="ltr" lang="en">
      <head>
        <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
        <meta name="x-apple-disable-message-reformatting" />
      </head>
      <body
        style='background-color:white;padding-top:2.5rem;padding-bottom:2.5rem;font-family:ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";color:#111827'>
        <table
          align="center"
          width="100%"
          border="0"
          cellpadding="0"
          cellspacing="0"
          role="presentation"
          style="margin-left:auto;margin-right:auto;max-width:36rem;border-radius:1rem;background-color:#f4f4f5;padding-left:2rem;padding-right:2rem;padding-top:4rem;padding-bottom:4rem">
          <tbody>
            <tr style="width:100%">
              <td>
                <table
                  align="center"
                  width="100%"
                  border="0"
                  cellpadding="0"
                  cellspacing="0"
                  role="presentation"
                  style="width:2.75rem;height:2.75rem;text-align:center">
                  <tbody>
                    <tr>
                      <td>
                        <img
                          alt="Quill"
                          src=${STATIC_ASSETS.logo}
                          style="margin-left:auto;margin-right:auto;margin-bottom:1rem;width:2.75rem;height:2.75rem;object-fit:contain;display:block;outline:none;border:none;text-decoration:none" />
                      </td>
                    </tr>
                  </tbody>
                </table>
                <h1
                  style="text-align:center;font-size:1.5rem;line-height:2rem;font-weight:600;color:#111827">
                  Reset your password
                </h1>
                <p
                  style="margin-left:auto;margin-right:auto;max-width:24rem;text-align:center;font-size:0.875rem;line-height:1.25rem;margin-top:16px;margin-bottom:24px;color:#3f3f46">
                  We received a request to reset your password. Click the button below to create a new one. This link is valid for 15 minutes.
                </p>
                <table
                  align="center"
                  border="0"
                  cellpadding="0"
                  cellspacing="0"
                  role="presentation"
                  style="text-align:center;margin-bottom:2rem">
                  <tr>
                    <td>
                      <a
                        href="${resetUrl}"
                        target="_blank"
                        style="border-radius:0.5rem;background-color:#7c3aed;padding:12px 24px;font-size:0.875rem;line-height:1.25rem;font-weight:600;color:white;text-decoration:none;display:inline-block">
                        Reset Password
                      </a>
                    </td>
                  </tr>
                </table>
                <p
                  style="text-align:center;font-size:0.75rem;line-height:1rem;color:#a1a1aa;margin-top:16px;margin-bottom:16px">
                  If you didn’t request this, you can ignore this email.
                </p>
                <p
                  style="text-align:center;font-size:0.75rem;line-height:1rem;color:#a1a1aa;margin-top:8px;margin-bottom:16px">
                  © 2025 Quill. All rights reserved.
                </p>
              </td>
            </tr>
          </tbody>
        </table>
      </body>
    </html>
  `

  return {
    html,
    text: `You requested to reset your password. Click the link below to continue:\n\n${resetUrl}\n\nIf you didn’t request this, you can safely ignore this email. The link is valid for 15 minutes.`
  }
}
