export default defineNuxtRouteMiddleware(async (to, from) => {
  const userStore = useUserStore()

  if (!userStore.isLoggedIn) {
    await userStore.fetchUser()
  }

  if (!userStore.isLoggedIn) {
    // Redirect to login, saving the redirect path
    return navigateTo({
      path: '/login',
      query: {
        redirect: to.fullPath,
      },
    })
  }
})
