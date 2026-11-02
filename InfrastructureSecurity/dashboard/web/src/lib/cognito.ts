// Amazon Cognito user pool, called straight from the browser (no AWS SDK needed: these are Cognito's public
// sign-in calls). Only used when the portal's PORTAL_AUTH=cognito; the pool/client ids come from /api/auth/config.
// The app client must have "ALLOW_USER_PASSWORD_AUTH" switched on and no client secret.
// The ID token Cognito returns is handed to the portal once (/api/auth/cognito) and never kept in the browser.

export interface CognitoConfig {
  region: string
  user_pool_id: string
  client_id: string
}

export class CognitoError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

const FRIENDLY: Record<string, string> = {
  NotAuthorizedException: 'Wrong email or password.',
  UserNotFoundException: 'Wrong email or password.',
  UsernameExistsException: 'An account with this email already exists. Sign in instead.',
  InvalidPasswordException: '',            // Cognito's own message names the missing rule
  CodeMismatchException: 'That code is not right. Check the email and try again.',
  ExpiredCodeException: 'That code has expired. Ask for a new one.',
  LimitExceededException: 'Too many tries. Wait a few minutes and try again.',
  TooManyRequestsException: 'Too many tries. Wait a few minutes and try again.',
  TooManyFailedAttemptsException: 'Too many tries. Wait a few minutes and try again.',
  InvalidParameterException: '',
  UserNotConfirmedException: 'Confirm your email address first.',
}

async function call<T>(cfg: CognitoConfig, action: string, body: object): Promise<T> {
  let res: Response
  try {
    res = await fetch(`https://cognito-idp.${cfg.region}.amazonaws.com/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': `AWSCognitoIdentityProviderService.${action}` },
      body: JSON.stringify({ ClientId: cfg.client_id, ...body }),
    })
  } catch {
    throw new CognitoError('Network', 'Could not reach Amazon Cognito. Check the internet connection.')
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const code = String(data.__type ?? 'Unknown').split('#').pop() as string
    throw new CognitoError(code, FRIENDLY[code] || data.message || 'Amazon Cognito refused the request.')
  }
  return data as T
}

/** Email + password → Cognito ID token. */
export async function cognitoSignIn(cfg: CognitoConfig, email: string, password: string): Promise<string> {
  const data = await call<{ AuthenticationResult?: { IdToken: string }; ChallengeName?: string }>(cfg, 'InitiateAuth', {
    AuthFlow: 'USER_PASSWORD_AUTH',
    AuthParameters: { USERNAME: email, PASSWORD: password },
  })
  if (data.AuthenticationResult?.IdToken) return data.AuthenticationResult.IdToken
  if (data.ChallengeName === 'NEW_PASSWORD_REQUIRED')
    throw new CognitoError('NewPasswordRequired', 'Your account was made by an administrator and needs a new password first. Ask them to reset it.')
  throw new CognitoError(data.ChallengeName ?? 'Unknown', 'This account needs an extra sign-in step CyberSuite does not support yet.')
}

/** Create the account; Cognito emails a 6-digit code unless the pool confirms users automatically. */
export async function cognitoSignUp(cfg: CognitoConfig, name: string, email: string, password: string): Promise<{ confirmed: boolean }> {
  const data = await call<{ UserConfirmed?: boolean }>(cfg, 'SignUp', {
    Username: email,
    Password: password,
    UserAttributes: [{ Name: 'email', Value: email }, { Name: 'name', Value: name }],
  })
  return { confirmed: Boolean(data.UserConfirmed) }
}

export async function cognitoConfirm(cfg: CognitoConfig, email: string, code: string): Promise<void> {
  await call(cfg, 'ConfirmSignUp', { Username: email, ConfirmationCode: code })
}

export async function cognitoResendCode(cfg: CognitoConfig, email: string): Promise<void> {
  await call(cfg, 'ResendConfirmationCode', { Username: email })
}
