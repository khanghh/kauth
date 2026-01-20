import { body } from '@primeuix/themes/aura/card'
import { useHttpGet } from './http'

export interface User {
  id: string
  username: string
  fullName: string
  email: string
  picture?: string
}

export const useApi = () => {
  return {
    getCurrentUser: () => useHttpGet<User>('/api/account'),
  }
}

