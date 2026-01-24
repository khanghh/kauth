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
          Two-Factor Authentication
        </h1>
      </div>
      <p class="text-gray-600">
        Add an extra layer of security to your account
      </p>
    </div>

    <div v-if="errorMsg"
      class="p-3 px-4 rounded-lg mb-5 flex items-center bg-red-100 border border-red-200 text-red-800">
      <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
      <span>{{ errorMsg }}</span>
    </div>

    <!-- Loading state -->
    <div v-if="loading" class="flex items-center justify-center py-12">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="space-y-6">
      <TwofactorMethodCard
        title="Email Authentication"
        iconName="fa7-solid:envelope"
        iconBgClass="bg-blue-100"
        iconColorClass="text-blue-600"
        :enabled="emailEnabled"
        @toggle="toggleEmail">
        <template #description>
          <span>{{ email || 'No email address configured' }}</span>
        </template>
      </TwofactorMethodCard>

      <TwofactorMethodCard title="SMS Authentication" iconName="fa7-solid:mobile" iconBgClass="bg-green-100"
        iconColorClass="text-green-600" :enabled="smsEnabled" :disabled="!phoneNumber" @toggle="toggleSMS">
        <template #description>
          <span>{{ phoneNumber || 'No phone number added' }}</span>
        </template>
      </TwofactorMethodCard>

      <TwofactorMethodCard title="Authenticator App" iconName="fa7-solid:mobile-screen-button"
        iconBgClass="bg-purple-100"
        iconColorClass="text-purple-600" :enabled="totpEnabled" @toggle="toggleTOTP">
        <template #description>
          <span>Time-based verification codes</span>
        </template>
      </TwofactorMethodCard>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-xl p-6 mt-8">
      <div class="flex items-start">
        <Icon name="fa7-solid:shield-halved" class="text-blue-500 mt-1 mr-3 text-xl" />
        <div>
          <h3 class="font-medium text-blue-800 text-lg mb-2">Why Enable Two-Factor Authentication?</h3>
          <ul class="text-sm text-blue-700 space-y-2">
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Extra Security:</strong> Even if someone steals your password, they can't access your
                account without the second factor</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Protection Against Phishing:</strong> 2FA codes are unique and time-sensitive, making
                phishing attacks much harder</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Compliance:</strong> Many services and regulations now require or recommend 2FA for enhanced
                security</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Peace of Mind:</strong> Know that your account has an additional layer of protection</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">

definePageMeta({
  layout: 'dashboard',
})

useHead({
  title: useSiteTitle('Two-Factor Authentication'),
})

const api = useApi()

// State
const loading = ref(true)
const emailEnabled = ref(false)
const totpEnabled = ref(false)
const smsEnabled = ref(false)
const email = ref('')
const phoneNumber = ref('')

const errorMsg = ref('')

const showError = (message: string) => {
  errorMsg.value = message
}

// Toggle email 2FA
const toggleEmail = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const newState = target.checked
  const previousState = emailEnabled.value

  // Optimistically update the UI
  emailEnabled.value = newState

  try {
    await api.set2FAMethodEnabled('email', newState)
  } catch (error: any) {
    emailEnabled.value = previousState // Revert on error
    showError(error.message || 'Failed to update email authentication')
  }
}

// Toggle SMS 2FA (mock for now)
const toggleSMS = async (event: Event) => {
  if (!phoneNumber.value) {
    return
  }
  const target = event.target as HTMLInputElement
  const newState = target.checked
  const previousState = smsEnabled.value

  // Optimistically update the UI
  smsEnabled.value = newState

  try {
    await api.set2FAMethodEnabled('sms', newState)
  } catch (error: any) {
    smsEnabled.value = previousState // Revert on error
    showError(error.message || 'Failed to update SMS authentication')
  }
}

// Toggle TOTP 2FA
const toggleTOTP = async (event: Event) => {
  const target = event.target as HTMLInputElement
  const newState = target.checked
  const previousState = totpEnabled.value

  // If trying to enable TOTP, redirect to enrollment
  if (newState) {
    navigateTo('/two-factor/totp/enroll')
    return
  }

  // If disabling, confirm first
  const ok = confirm(
    'Are you sure you want to disable the authenticator app? You will need to set it up again to re-enable.'
  )
  if (!ok) {
    return
  }

  // Optimistically update the UI
  totpEnabled.value = newState

  try {
    await api.set2FAMethodEnabled('totp', newState)
  } catch (error: any) {
    totpEnabled.value = previousState // Revert on error
    showError(error.message || 'Failed to update authenticator app')
  }
}

// Load 2FA methods
const load2FAMethods = async () => {
  try {
    loading.value = true
    const methods = await api.get2FAMethods()

    methods.forEach(method => {
      if (method.type === 'email') {
        emailEnabled.value = method.enabled
        email.value = method.email || ''
      } else if (method.type === 'totp') {
        totpEnabled.value = method.enabled
      } else if (method.type === 'sms') {
        smsEnabled.value = method.enabled
        phoneNumber.value = method.phone || ''
      }
    })
  } catch (error: any) {
    showError(error.message || 'Failed to load 2FA methods')
  } finally {
    loading.value = false
  }
}

// Initialize
onMounted(async () => {
  await load2FAMethods()
})
</script>
