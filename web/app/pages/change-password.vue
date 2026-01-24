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
          Change Password
        </h1>
      </div>
      <p class="text-gray-600">
        Update your password to keep your account secure
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
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-lg font-semibold text-gray-800">Change Password</h2>
      </div>

      <form class="space-y-6" method="POST" @submit="onSubmit">
        <div>
          <label for="currentPassword" class="block text-sm font-medium text-gray-700 mb-2">Current Password</label>
          <div class="relative">
            <input
              :type="showCurrentPassword ? 'text' : 'password'"
              id="currentPassword"
              name="currentPassword"
              v-model="currentPassword"
              autocomplete="current-password"
              required
              class="w-full px-4 py-3 border border-gray-300 rounded-xl transition pr-10 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
              placeholder="Enter your current password" />
            <button
              type="button"
              class="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-indigo-600"
              @click="showCurrentPassword = !showCurrentPassword"
              aria-label="Toggle current password visibility">
              <Icon :name="showCurrentPassword ? 'fa-solid:eye-slash' : 'fa-solid:eye'" />
            </button>
          </div>
          <p v-if="currentPasswordError" class="mt-2 text-sm text-red-600">{{ currentPasswordError }}</p>
        </div>

        <div>
          <label for="newPassword" class="block text-sm font-medium text-gray-700 mb-2">New Password</label>
          <div class="relative">
            <input
              :type="showNewPassword ? 'text' : 'password'"
              id="newPassword"
              name="newPassword"
              v-model="newPassword"
              autocomplete="new-password"
              required
              class="w-full px-4 py-3 border border-gray-300 rounded-xl transition pr-10 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
              placeholder="Enter your new password" />
            <button
              type="button"
              class="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-indigo-600"
              @click="showNewPassword = !showNewPassword"
              aria-label="Toggle new password visibility">
              <Icon :name="showNewPassword ? 'fa-solid:eye-slash' : 'fa-solid:eye'" />
            </button>
          </div>

          <div class="mt-3">
            <div class="flex justify-between text-sm mb-1">
              <span class="text-gray-600">Password strength</span>
              <span class="font-medium" :class="strengthLabelClass">{{ strengthLabel }}</span>
            </div>
            <div class="h-2 rounded-full bg-gray-200 overflow-hidden">
              <div
                class="h-full transition-all duration-300"
                :class="strengthBarColorClass"
                :style="{ width: strengthMeterWidth }">
              </div>
            </div>
          </div>

          <p v-if="passwordError" class="mt-2 text-sm text-red-600">{{ passwordError }}</p>
        </div>

        <div>
          <label for="confirmPassword" class="block text-sm font-medium text-gray-700 mb-2">Confirm New Password</label>
          <div class="relative">
            <input
              :type="showConfirmPassword ? 'text' : 'password'"
              id="confirmPassword"
              name="confirmPassword"
              v-model="confirmPassword"
              autocomplete="new-password"
              required
              class="w-full px-4 py-3 border border-gray-300 rounded-xl transition pr-10 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
              placeholder="Re-enter your new password" />
            <button
              type="button"
              class="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-indigo-600"
              @click="showConfirmPassword = !showConfirmPassword"
              aria-label="Toggle confirm password visibility">
              <Icon :name="showConfirmPassword ? 'fa-solid:eye-slash' : 'fa-solid:eye'" />
            </button>
          </div>

          <div v-if="confirmPassword.length > 0" class="mt-2 text-sm">
            <span v-if="passwordsMatch" class="text-green-600 inline-flex items-center">
              <Icon name="fa-solid:check" class="mr-1" />
              Passwords match
            </span>
            <span v-else class="text-red-600 inline-flex items-center">
              <Icon name="fa-solid:xmark" class="mr-1" />
              Passwords do not match
            </span>
          </div>

          <p v-if="confirmPasswordError" class="mt-2 text-sm text-red-600">{{ confirmPasswordError }}</p>
        </div>



        <div class="flex items-center justify-between pt-6 border-t border-gray-200">
          <div v-if="lastPasswordChange" class="text-sm text-gray-500">Last password change: {{ lastPasswordChange }}
          </div>
          <div v-else class="text-sm text-gray-500">&nbsp;</div>

          <div class="flex space-x-3">
            <NuxtLink
              to="/"
              class="px-4 py-2 rounded-xl border border-gray-300 text-gray-700 hover:bg-gray-50 transition">
              Cancel
            </NuxtLink>
            <button
              type="submit"
              class="px-5 py-2 rounded-xl font-medium transition"
              :class="canSubmit ? 'bg-indigo-600 hover:bg-indigo-700 text-white' : 'bg-gray-200 text-gray-500 cursor-not-allowed'"
              :disabled="!canSubmit">
              Change Password
            </button>
          </div>
        </div>
      </form>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
      <div class="flex items-start">
        <Icon name="fa7-solid:shield-halved" class="text-blue-500 mt-1 mr-3" />
        <div>
          <h3 class="font-medium text-blue-800 mb-2">Password Security Tips</h3>
          <ul class="text-sm text-blue-700 space-y-1">
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span>Use a unique password that you don't use for other accounts</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span>Consider using a password manager to generate and store secure passwords</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span>Avoid using personal information like your name, birthdate, or common words</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span>Change your password regularly for better security</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped></style>

<script setup lang="ts">
import auth from '~/middlewares/auth'

const api = useApi()

definePageMeta({
  layout: 'dashboard',
  middleware: auth
})

useHead({
  title: useSiteTitle('Change password'),
})

const errorMsg = ref('')
const successMsg = ref('')
const lastPasswordChange = ref('')

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')

const passwordError = ref('')
const currentPasswordError = ref('')
const confirmPasswordError = ref('')

const showSuccess = (msg: string) => {
  successMsg.value = msg
  errorMsg.value = ''
}

const showError = (msg: string) => {
  errorMsg.value = msg
  successMsg.value = ''
}

const showCurrentPassword = ref(false)
const showNewPassword = ref(false)
const showConfirmPassword = ref(false)

const strengthScore = computed(() => {
  const pwd = newPassword.value
  let score = 0
  if (pwd.length >= 8) score++
  if (/[a-z]/.test(pwd)) score++
  if (/[A-Z]/.test(pwd)) score++
  if (/[0-9]/.test(pwd)) score++
  if (/[^A-Za-z0-9]/.test(pwd)) score++
  return score
})

const strengthLabel = computed(() => {
  if (newPassword.value.length === 0) return 'None'
  if (strengthScore.value <= 2) return 'Weak'
  if (strengthScore.value <= 4) return 'Medium'
  return 'Strong'
})

const strengthLabelClass = computed(() => {
  if (newPassword.value.length === 0) return 'text-gray-500'
  if (strengthScore.value <= 2) return 'text-red-600'
  if (strengthScore.value <= 4) return 'text-yellow-600'
  return 'text-green-600'
})

const strengthMeterWidth = computed(() => {
  if (newPassword.value.length === 0) return '0%'
  if (strengthScore.value <= 2) return '33%'
  if (strengthScore.value <= 4) return '66%'
  return '100%'
})

const strengthBarColorClass = computed(() => {
  if (newPassword.value.length === 0) return 'bg-gray-300'
  if (strengthScore.value <= 2) return 'bg-red-500'
  if (strengthScore.value <= 4) return 'bg-yellow-500'
  return 'bg-green-500'
})

const passwordsMatch = computed(() => {
  if (!newPassword.value || !confirmPassword.value) return false
  return newPassword.value === confirmPassword.value
})

const canSubmit = computed(() => {
  return Boolean(currentPassword.value) && newPassword.value.length >= 6 && passwordsMatch.value
})

watch(newPassword, () => {
  passwordError.value = ''
  confirmPasswordError.value = ''
})

watch(confirmPassword, () => {
  confirmPasswordError.value = ''
})

const validate = () => {
  currentPasswordError.value = ''
  confirmPasswordError.value = ''
  passwordError.value = ''

  let valid = true

  if (!currentPassword.value) {
    currentPasswordError.value = 'Current password is required.'
    valid = false
  }

  if (newPassword.value.length < 6) {
    passwordError.value = 'Password must be at least 6 characters.'
    valid = false
  }

  if (newPassword.value !== confirmPassword.value) {
    confirmPasswordError.value = 'Passwords do not match.'
    valid = false
  }

  return valid
}

const onSubmit = async (e: Event) => {
  e.preventDefault()

  if (!validate()) {
    return
  }

  try {
    await api.changePassword(currentPassword.value, newPassword.value)
    showSuccess('Password changed successfully!')
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
  } catch (err: any) {
    showError(err?.message ?? 'Failed to change password')
  }
}
</script>
