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
          Connected Accounts
        </h1>
      </div>
      <p class="text-gray-600">
        Manage your connected third-party accounts and services
      </p>
    </div>

    <div v-if="successMsg" class="mb-6 rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-green-800">
      <div class="flex items-center">
        <Icon name="fa7-solid:circle-check" class="mr-2" />
        <span>{{ successMsg }}</span>
      </div>
    </div>

    <div v-if="errorMsg" class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-red-800">
      <div class="flex items-center">
        <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
        <span>{{ errorMsg }}</span>
      </div>
    </div>

    <div v-if="loading" class="flex items-center justify-center py-12">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="space-y-4">
      <OauthAccountCard
        v-for="account in accounts"
        :key="account.provider"
        :account="account"
        :iconName="providerIcons[account.provider] || 'fa7-solid:link'"
        :iconClass="providerColors[account.provider]?.text || 'text-gray-600'"
        @connect="handleConnect(account.provider)"
        @disconnect="handleDisconnect(account)" />
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
import { onMounted, ref } from 'vue'
import type { OAuthAccount } from '~/composables/useApi'
import auth from '~/middlewares/auth'

const api = useApi()

definePageMeta({
  layout: 'dashboard',
  middleware: auth
})

useHead({ title: useSiteTitle('Connected Accounts') })

const accounts = ref<OAuthAccount[]>([])
const loading = ref(true)
const processing = ref<string | null>(null)
const successMsg = ref('')
const errorMsg = ref('')

const providerIcons: Record<string, string> = {
  google: 'fa7-brands:google',
  facebook: 'fa7-brands:facebook',
  apple: 'fa7-brands:apple',
  microsoft: 'fa7-brands:microsoft',
  discord: 'fa7-brands:discord',
}

const providerColors: Record<string, { text: string }> = {
  google: { text: 'text-red-500' },
  facebook: { text: 'text-blue-600' },
  apple: { text: 'text-gray-800' },
  microsoft: { text: 'text-blue-700' },
  discord: { text: 'text-indigo-600' },
}

const showError = (msg: string) => { successMsg.value = ''; errorMsg.value = msg }

const fetchAccounts = async () => {
  try {
    loading.value = true
    const fetchedAccounts = await api.getOAuthAccounts()

    accounts.value = fetchedAccounts
  } catch (err: any) {
    showError(err?.message ?? 'Failed to fetch connected accounts')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchAccounts()
})

const handleDisconnect = async (account: OAuthAccount) => {
  const provider = account.provider
  if (!confirm(`Are you sure you want to disconnect your ${provider} account? This may affect your ability to sign in.`)) return
  try {
    processing.value = provider
    await api.disconnectOAuthAccount(provider)

    await fetchAccounts()
  } catch (err: any) {
    showError(err?.message ?? `Failed to disconnect ${provider}`)
  } finally {
    processing.value = null
  }
}

const handleConnect = async (provider: string) => {
  const account = accounts.value.find(a => a.provider === provider)
  const connectUrl = account?.connectUrl
  if (!connectUrl) {
    showError(`Missing connect URL for ${provider}`)
    return
  }

  processing.value = provider
  // External redirect to provider auth URL.
  await navigateTo(connectUrl, { external: true })
}
</script>
