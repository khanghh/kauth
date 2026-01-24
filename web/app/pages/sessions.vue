<template>
  <div class="max-w-4xl mx-auto">
    <div class="mb-8">
      <div class="flex items-center mb-2">
        <NuxtLink
          to="/"
          aria-label="Back"
          class="md:hidden flex items-center mr-2">
          <Icon name="fa7-solid:arrow-left" class="text-gray-700 w-8 h-8" />
        </NuxtLink>
        <h1 class="text-2xl font-bold text-gray-800 leading-none">
          Active Sessions
        </h1>
      </div>
      <p class="text-gray-600">
        Manage your active sessions
      </p>
    </div>

    <div v-if="successMsg" class="mb-6 rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-green-800">
      <div class="flex items-center">
        <Icon name="fa-solid:check-circle" class="mr-2" />
        <span>{{ successMsg }}</span>
      </div>
    </div>

    <div v-if="errorMsg" class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-red-800">
      <div class="flex items-center">
        <Icon name="fa-solid:exclamation-circle" class="mr-2" />
        <span>{{ errorMsg }}</span>
      </div>
    </div>

    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-800 mb-6">Connected Services</h2>
      <div class="space-y-4">
        <div class="service-card flex items-center justify-between p-4 border border-gray-200 rounded-xl">
          <div class="flex items-center">
            <div class="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mr-4">
              <Icon name="fa-brands:google" class="text-blue-600" />
            </div>
            <div>
              <div class="flex items-center gap-2">
                <div class="font-medium text-gray-800">Google</div>
                <span
                  class="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full inline-flex items-center">Connected</span>
              </div>
              <div class="text-sm text-gray-500">{{ email }}</div>
            </div>
          </div>
          <div class="flex items-center space-x-2">
            <button type="button" class="text-red-600 hover:text-red-800 text-sm font-medium"
              @click="disconnectGoogle">
              Disconnect
            </button>
          </div>
        </div>

        <div class="service-card flex items-center justify-between p-4 border border-gray-200 rounded-xl">
          <div class="flex items-center">
            <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
              <Icon name="fa-brands:github" class="text-gray-800" />
            </div>
            <div>
              <div class="font-medium text-gray-800">GitHub</div>
              <div class="text-sm text-gray-500">Not connected</div>
            </div>
          </div>
          <button
            type="button"
            class="px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900 text-sm font-medium transition"
            @click="connectGithub">
            Connect
          </button>
        </div>
      </div>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
      <div class="flex items-start">
        <Icon name="fa7-solid:shield-halved" class="text-blue-500 mr-3 text-2xl" />
        <div>
          <h3 class="font-medium text-blue-800 mb-1">About Connected Accounts</h3>
          <p class="text-sm text-blue-700">
            Connected accounts allow you to link your account with third-party services for easier login and improved
            functionality.
            You can connect or disconnect services at any time from this page.
          </p>
        </div>
      </div>
    </div>
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
