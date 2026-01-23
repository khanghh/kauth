import { useUserStore } from '~/stores/user'

export default defineNuxtRouteMiddleware(async (to) => {
  if (import.meta.server) return

  const userStore = useUserStore()

  if (!userStore.isLoggedIn) {
    await userStore.fetchUser()
  }

  if (!userStore.isLoggedIn) {
    return navigateTo({
      path: '/login',
      query: { redirect: to.fullPath },
    })
  }
})
