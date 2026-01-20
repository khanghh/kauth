<template>
  <div>
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <div class="w-24 h-24 mx-auto bg-blue-100 flex items-center justify-center rounded-full mb-4">
          <i class="fa-solid fa-lock text-blue-500 text-5xl" aria-hidden="true"></i>
        </div>
        <h1 class="text-3xl font-bold text-gray-800 mb-4">Set New Password</h1>
        <p class="text-gray-600 mt-2 mb-6">
          Create a new password for your account. Make sure it's strong and secure.
        </p>
      </div>

      <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
        <i class="fas fa-exclamation-circle mr-2"></i>
        {{ errorMsg }}
      </div>

      <form id="setPasswordForm" method="POST" @submit.prevent="handleSubmit" class="space-y-4 text-left">
        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Create password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <i class="fas fa-lock"></i>
            </span>
            <input
              v-model="form.newPassword"
              type="password"
              id="newPassword"
              name="newPassword"
              autocomplete="new-password"
              required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Create a secure password"
              @input="checkPasswordStrength">
            <span class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
              @click="togglePasswordVisibility('newPassword')">
              <i :class="passwordVisible.newPassword ? 'fas fa-eye-slash' : 'fas fa-eye'"></i>
            </span>
          </div>

          <div class="mt-2" :class="{ hidden: !form.newPassword }" id="passwordStrengthContainer">
            <div class="flex bg-gray-200 rounded-full overflow-hidden h-1.5">
              <div id="passwordStrength" :class="['strength-bar', passwordStrengthClass]"></div>
            </div>
            <p id="passwordStrengthText" :class="['text-xs mt-1', passwordStrengthTextClass]">{{ passwordStrengthText
            }}
            </p>
          </div>
          <p id="passwordError" class="mt-1 text-sm text-red-600" v-if="passwordError">{{ passwordError }}</p>
        </div>

        <div>
          <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-1">Confirm password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <i class="fas fa-lock"></i>
            </span>
            <input
              v-model="form.confirmPassword"
              type="password"
              id="confirm_password"
              name="confirm_password"
              autocomplete="new-password"
              required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Confirm your password"
              @input="checkConfirmPassword">
            <span class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
              @click="togglePasswordVisibility('confirmPassword')">
              <i :class="passwordVisible.confirmPassword ? 'fas fa-eye-slash' : 'fas fa-eye'"></i>
            </span>
          </div>
          <p id="confirmPasswordError" class="mt-1 text-sm text-red-600" :class="{ hidden: !confirmPasswordError }"
            v-if="confirmPasswordError">{{ confirmPasswordError }}</p>
        </div>

        <input type="hidden" name="_csrf" :value="csrfToken">
        <div v-if="turnstileSiteKey" class="cf-turnstile text-center" :data-sitekey="turnstileSiteKey"></div>
        <div class="pt-2">
          <button type="submit"
            class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center">
            Confirm
          </button>
        </div>
      </form>

      <div class="mt-6 text-center">
        <a href="/login" class="text-blue-600 hover:underline font-medium">
          <i class="fas fa-arrow-left mr-1"></i>
          Back to Login
        </a>
      </div>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Need help? <a href="#" class="text-blue-600 hover:underline font-medium">Contact Support</a>
      </p>
    </footer>
  </div>
</template>

<style scoped>
.avatar {
  transition: all 0.3s ease;
}

.avatar:hover {
  transform: scale(1.05);
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
}

.form-input:focus {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}

.password-toggle {
  cursor: pointer;
  transition: color 0.2s;
}

.password-toggle:hover {
  color: #3b82f6;
}

.strength-bar {
  height: 5px;
  border-radius: 3px;
  transition: width 0.3s, background-color 0.3s;
}

.strength-weak {
  background-color: #ef4444;
  width: 33%;
}

.strength-medium {
  background-color: #f59e0b;
  width: 66%;
}

.strength-strong {
  background-color: #10b981;
  width: 100%;
}
</style>

<script setup lang="ts">
const route = useRoute()
const config = useRuntimeConfig()

// Assuming props or route params for token, etc.
const token = route.query.token as string
const csrfToken = '' // Fetch or set CSRF token
const turnstileSiteKey = '' // Set if needed

const form = reactive({
  newPassword: '',
  confirmPassword: ''
})

const passwordVisible = reactive({
  newPassword: false,
  confirmPassword: false
})

const errorMsg = ref('')
const passwordError = ref('')
const confirmPasswordError = ref('')
const isSubmitting = ref(false)

const passwordStrength = ref(0)

const passwordStrengthClass = computed(() => {
  if (passwordStrength.value <= 2) return 'strength-weak'
  if (passwordStrength.value <= 4) return 'strength-medium'
  return 'strength-strong'
})

const passwordStrengthText = computed(() => {
  if (!form.newPassword) return 'Enter a password'
  if (passwordStrength.value <= 2) return 'Password strength: Weak'
  if (passwordStrength.value <= 4) return 'Password strength: Medium'
  return 'Password strength: Strong'
})

const passwordStrengthTextClass = computed(() => {
  if (!form.newPassword) return 'text-gray-500'
  if (passwordStrength.value <= 2) return 'text-red-500'
  if (passwordStrength.value <= 4) return 'text-yellow-500'
  return 'text-green-500'
})

const togglePasswordVisibility = (field: 'newPassword' | 'confirmPassword') => {
  passwordVisible[field] = !passwordVisible[field]
}

const checkPasswordStrength = () => {
  const password = form.newPassword
  let strength = 0
  passwordError.value = ''
  confirmPasswordError.value = ''

  if (password.length >= 8) strength++
  if (/[a-z]/.test(password)) strength++
  if (/[A-Z]/.test(password)) strength++
  if (/[0-9]/.test(password)) strength++
  if (/[^A-Za-z0-9]/.test(password)) strength++

  passwordStrength.value = strength
}

const checkConfirmPassword = () => {
  const password = form.newPassword
  const confirmPassword = form.confirmPassword
  if (password !== confirmPassword) {
    confirmPasswordError.value = 'Passwords do not match.'
  } else {
    confirmPasswordError.value = ''
  }
}

const handleSubmit = async () => {
  passwordError.value = ''
  confirmPasswordError.value = ''

  const password = form.newPassword
  if (password.length < 6) {
    passwordError.value = 'Password must be at least 6 characters.'
    return
  }

  const confirmPassword = form.confirmPassword
  if (password !== confirmPassword) {
    confirmPasswordError.value = 'Passwords do not match.'
    return
  }

  isSubmitting.value = true

  try {
    await $fetch('/api/reset-password', {
      method: 'POST',
      body: {
        token,
        newPassword: form.newPassword,
        confirmPassword: form.confirmPassword,
        _csrf: csrfToken
      }
    })
    // Redirect or show success
    await navigateTo('/login')
  } catch (err: any) {
    errorMsg.value = err.data?.message || 'An error occurred. Please try again.'
  } finally {
    isSubmitting.value = false
  }
}
</script>
