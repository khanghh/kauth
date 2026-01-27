<template>
  <div class="max-w-4xl mx-auto text-center py-20">
    <h1 class="text-3xl font-bold text-gray-800 mb-2">Coming Soon</h1>
    <p class="text-gray-600">Connected Accounts and Active Sessions will be available soon.</p>
  </div>
</template>

<style scoped></style>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { PersonalInfo } from '~/composables/useApi'
import auth from '~/middlewares/auth'

const api = useApi()

definePageMeta({
  layout: 'dashboard',
  middleware: auth
})

useHead({ title: useSiteTitle('Connected Accounts') })

const profile = ref<PersonalInfo>({} as PersonalInfo)

onMounted(async () => {
  try {
    const data = await api.getPersonalInfo()
    profile.value = data
  } catch (err: any) {
    if (err?.code === 401 || err?.statusCode === 401) return
    showError(err?.message ?? 'Failed to fetch profile')
  }
})

const email = computed(() => profile.value?.email ?? '')

const successMsg = ref('')
const errorMsg = ref('')
const showSuccess = (msg: string) => { errorMsg.value = ''; successMsg.value = msg }
const showError = (msg: string) => { successMsg.value = ''; errorMsg.value = msg }

const disconnectGoogle = () => {
  if (!confirm('Are you sure you want to disconnect your Google account? This may affect your ability to sign in.')) return
  showSuccess('Google account disconnected. (mock)')
}

const connectGithub = () => {
  showSuccess('Redirecting to GitHub authorization... (mock)')
}
</script>
