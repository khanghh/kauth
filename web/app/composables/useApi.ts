import { useHttpGet } from './http'

export interface User {
  userId: string
  username: string
  fullName: string
  email: string
  picture?: string
}

export const useApi = () => {
  return {
    getCurrentUser: () => useHttpGet<User>('/api/me')
  }
}

