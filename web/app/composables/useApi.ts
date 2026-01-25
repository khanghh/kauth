import { useHttpGet, useHttpPatch, useHttpPost } from './http'

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
}

export const useApi = () => {
  return {
    getCurrentUser: () => useHttpGet<UserInfo>('/api/account'),
    getPersonalInfo: () => useHttpGet<PersonalInfo>('/api/account/personal-info'),
    updatePersonalInfo(update: PersonalInfoUpdate): Promise<PersonalInfo> {
      return useHttpPatch<PersonalInfo>('/api/account/personal-info', { body: update })
    },
    changePassword(currentPassword: string, newPassword: string) {
      return useHttpPost('/api/account/change-password', {
        body: {
          currentPassword, newPassword
        }
      })
    },
    get2FAMethods: () => useHttpGet<TwoFactorMethod[]>('/api/account/2fa'),
    set2FAMethodEnabled(method: string, enabled: boolean) {
      return useHttpPatch(`/api/account/2fa/${method}`, {
        body: { enabled }
      })
    },
    getTOTPEnrollment(renew?: boolean): Promise<TOTPSetup> {
      return useHttpGet('/api/account/2fa/totp/enroll', {
        params: { renew }
      })
    },
    enrollTOTP(code: string) {
      return useHttpPost('/api/account/2fa/totp/enroll', {
        body: { code }
      })
    },
    getOAuthAccounts: () => useHttpGet<OAuthAccount[]>('/api/account/oauth')
  }
}
