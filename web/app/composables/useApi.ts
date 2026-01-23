import { useHttpGet } from './http'

export interface UserInfo {
  id: string
  username: string
  fullName: string
  email: string
  picture?: string
}

export interface UserProfile extends UserInfo {
  birthDay: number
  phoneNumber?: string
  country?: string
  timeZone?: string
}

export interface Challenge {
  cid: string
  type: string
  method?: string
  target?: string
}

export const useApi = () => {
  return {
    getCurrentUser: () => useHttpGet<UserInfo>('/api/account'),
    getUserProfile: () => useHttpGet<UserProfile>('/api/account/profile'),
    changePassword: (currentPassword: string, newPassword: string) => {
      return useHttpPost("/api/account/change-password", {
        body: {
          currentPassword, newPassword
        }
      })
    }
  }
}
