import { useHttpDelete, useHttpGet, useHttpPatch, useHttpPost } from './http'

export interface UserInfo {
  id: string
  username: string
  fullName: string
  email: string
  picture?: string
}

export interface PersonalInfo extends UserInfo {
  birthday?: number
  gender?: string
  phoneNumber?: string
  country?: string
}

export interface Challenge {
  cid: string
  type: string
  method?: string
  target?: string
}

export interface PersonalInfoUpdate {
  fullName?: string
  birthday?: number
  gender?: string
  phoneNumber?: string
  country?: string
}

export interface TwoFactorMethod {
  type: string
  enabled: boolean
  email: string
  phone: string
}

export interface TOTPSetup {
  secret: string
  enrollmentUrl: string
}

export interface OAuthAccount {
  provider: string
  accountId: string
  displayName: string
  email: string
  picture: string
  connected: boolean
  connectUrl?: string
}

export enum AccountEventType {
  LoginSuccess = "auth.login.success",
  LoginFailure = "auth.login.failure",
  UserLogout = "auth.logout",
  ServiceAuthorized = "auth.service.authorized",
  TwoFAChallengeCreated = "auth.2fa.challenge.created",
  TwoFAAttemptSuccess = "auth.2fa.attempt.success",
  TwoFAAttemptFailure = "auth.2fa.attempt.failure",
}

export interface AccountEvent {
  sessionId: string
  eventType: AccountEventType
  authMethod?: string
  challengeType?: string
  service?: string
  callbackUrl?: string
  reason?: string
  ip: string
  userAgent: string
  createdAt: number
}

export interface CursorResponse<T> {
  items: T[]
  cursor: number
  hasMore: boolean
}

export const useApi = () => {
  return {
    getCurrentUser() {
      return useHttpGet<UserInfo>('/api/account')
    },
    getPersonalInfo() {
      return useHttpGet<PersonalInfo>('/api/account/personal-info')
    },
    updatePersonalInfo(update: PersonalInfoUpdate) {
      return useHttpPatch<PersonalInfo>('/api/account/personal-info', { body: update })
    },
    changePassword(currentPassword: string, newPassword: string) {
      return useHttpPost('/api/account/change-password', {
        body: { currentPassword, newPassword }
      })
    },
    get2FAMethods() {
      return useHttpGet<TwoFactorMethod[]>('/api/account/2fa')
    },
    set2FAMethodEnabled(method: string, enabled: boolean) {
      return useHttpPatch(`/api/account/2fa/${method}`, {
        body: { enabled }
      })
    },
    getTOTPEnrollment(renew?: boolean) {
      return useHttpGet<TOTPSetup>('/api/account/2fa/totp/enroll', {
        params: { renew }
      })
    },
    enrollTOTP(code: string) {
      return useHttpPost('/api/account/2fa/totp/enroll', {
        body: { code }
      })
    },
    getOAuthAccounts() {
      return useHttpGet<OAuthAccount[]>('/api/account/oauth')
    },
    disconnectOAuthAccount(provider: string) {
      return useHttpDelete(`/api/account/oauth/${provider}`)
    },
    getRecentActivities(cursor?: number) {
      return useHttpGet<CursorResponse<AccountEvent>>('/api/account/events', {
        params: { cursor }
      })
    }
  }
}
