import { defineStore } from 'pinia'


export const useUserStore = defineStore('user', () => {
  const api = useApi()
  const user = ref<User | null>(null)

  const isFetching = ref(false)

  const isLoggedIn = computed(() => !!user.value)

  async function fetchUser() {
    if (user.value) return

    isFetching.value = true
    try {
      const data = await api.getCurrentUser()
      user.value = data
    } catch (error) {
      user.value = null
    } finally {
      isFetching.value = false
    }
  }

  async function logout() {
    try {
      await $fetch('/logout', { method: 'POST' })
    } catch (e) {
      // ignore error
    } finally {
      user.value = null
      navigateTo('/login')
    }
  }

  return {
    user,
    isFetching,
    isLoggedIn,
    fetchUser,
    logout
  }
})
