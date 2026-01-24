import PersonalInfo from '~/pages/personal-info.vue'
import { useHttpGet } from './http'

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

export const useApi = () => {
  return {
    getCurrentUser: () => useHttpGet<UserInfo>('/api/account'),
    getPersonalInfo: () => useHttpGet<PersonalInfo>('/api/account/personal-info'),
    updatePersonalInfo: (update: PersonalInfoUpdate) => {
      return useHttpPatch<PersonalInfo>("/api/account/personal-info", { body: update })
    },
    changePassword: (currentPassword: string, newPassword: string) => {
      return useHttpPost("/api/account/change-password", {
        body: {
          currentPassword, newPassword
        }
      })
    }
  }
}
