<template>
  <div>
    <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
      <div v-if="success" class="px-6 sm:px-10 py-10 text-center">
        <div class="w-24 h-24 mx-auto bg-green-100 flex items-center justify-center rounded-full mb-4">
          <Icon name="fa7-solid:circle-check" class="text-green-500 text-5xl" aria-hidden="true" />
        </div>
        <h1 class="text-3xl font-bold text-gray-800 mb-2">Password Updated</h1>
        <p class="text-gray-600">
          Your password has been successfully updated. You can now log in with your new password.
        </p>

        <div class="mt-6 flex flex-row gap-3 justify-center">
          <a href="/login"
            class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
            <Icon name="fa7-solid:sign-in-alt" class="mr-2" />
            Go to Login
          </a>
        </div>
      </div>

      <div v-else class="px-6 sm:px-10 py-10 ">
        <div class="text-center mb-8">
          <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
          <h1 class="text-3xl font-bold text-gray-800 mb-2">Set New Password</h1>
          <p class="text-gray-600">
            Create a new password for your account. Make sure it's strong and secure.
          </p>
        </div>

        <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
          <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
          {{ errorMsg }}
        </div>

        <form id="setPasswordForm" method="POST" class="space-y-4 text-left" @submit="onSubmit">
          <div>
            <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Create password</label>
            <div class="relative">
              <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <Icon name="fa7-solid:lock" />
              </span>
              <input v-model="newPassword" :type="showPassword ? 'text' : 'password'" id="newPassword"
                name="newPassword"
                autocomplete="new-password" required
                class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                placeholder="Create a secure password" @input="onPasswordInput">
              <span class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
                @click="toggleShowPassword">
                <Icon :name="showPassword ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
              </span>
            </div>

            <div class="mt-2" :class="{ hidden: !showStrength }" id="passwordStrengthContainer">
              <div class="flex bg-gray-200 rounded-full overflow-hidden h-1.5">
                <div :class="strengthClass" id="passwordStrength"></div>
              </div>
              <p id="passwordStrengthText" :class="strengthTextClass">{{ strengthText }}</p>
            </div>
            <p id="passwordError" class="mt-1 text-sm text-red-600" v-if="clientPasswordError || serverPasswordError">{{
              clientPasswordError || serverPasswordError }}</p>
          </div>

          <div>
            <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-1">Confirm password</label>
            <div class="relative">
              <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <Icon name="fa7-solid:lock" />
              </span>
              <input v-model="confirmPassword" :type="showConfirm ? 'text' : 'password'" id="confirm_password"
                name="confirm_password" autocomplete="new-password" required
                class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                placeholder="Confirm your password" @input="onConfirmInput">
              <span class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
                @click="toggleShowConfirm">
                <Icon :name="showConfirm ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
              </span>
            </div>
            <p id="confirmPasswordError" class="mt-1 text-sm text-red-600" v-if="clientConfirmError">{{
              clientConfirmError
              }}</p>
          </div>

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
            <Icon name="fa7-solid:arrow-left" class="mr-1" />
            Back to Login
          </a>
        </div>
      </div>

      <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
        <p class="text-gray-500 text-xs sm:text-sm">
          Need help? <a :href="contactLink" class="text-blue-600 hover:underline font-medium">Contact Support</a>
        </p>
      </footer>
    </div>
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
import { ref } from 'vue'

useHead({
  title: useSiteTitle('Reset Password'),
  script: [
    {
      src: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
      defer: true
    }
  ]
})

const config = useRuntimeConfig().public
const turnstileSiteKey = config.turnstileSiteKey
const contactLink = config.contactLink as string || '#'

const success = useServerVar<boolean>('success', false)
const errorMsg = useServerVar<string>('errorMsg', '')
const serverPasswordError = useServerVar<string>('passwordError', '')

const newPassword = ref('')
const confirmPassword = ref('')
const showPassword = ref(false)
const showConfirm = ref(false)
const showStrength = ref(false)
const strengthClass = ref('strength-bar')
const strengthText = ref('Enter a password')
const strengthTextClass = ref('text-xs mt-1 text-gray-500')
const clientPasswordError = ref('')
const clientConfirmError = ref('')

function evaluateStrength(pw: string) {
  let strength = 0
  if (pw.length >= 8) strength++
  if (/[a-z]/.test(pw)) strength++
  if (/[A-Z]/.test(pw)) strength++
  if (/[0-9]/.test(pw)) strength++
  if (/[^A-Za-z0-9]/.test(pw)) strength++

  if (pw.length > 0) {
    showStrength.value = true
  } else {
    showStrength.value = false
  }

  if (pw.length === 0) {
    strengthClass.value = 'strength-bar'
    strengthText.value = 'Enter a password'
    strengthTextClass.value = 'text-xs mt-1 text-gray-500'
  } else if (strength <= 2) {
    strengthClass.value = 'strength-bar strength-weak'
    strengthText.value = 'Password strength: Weak'
    strengthTextClass.value = 'text-xs mt-1 text-red-500'
  } else if (strength <= 4) {
    strengthClass.value = 'strength-bar strength-medium'
    strengthText.value = 'Password strength: Medium'
    strengthTextClass.value = 'text-xs mt-1 text-yellow-500'
  } else {
    strengthClass.value = 'strength-bar strength-strong'
    strengthText.value = 'Password strength: Strong'
    strengthTextClass.value = 'text-xs mt-1 text-green-500'
  }
}

function onPasswordInput() {
  clientPasswordError.value = ''
  clientConfirmError.value = ''
  evaluateStrength(newPassword.value)
}

function onConfirmInput() {
  clientConfirmError.value = ''
  if (newPassword.value !== confirmPassword.value) {
    clientConfirmError.value = 'Passwords do not match.'
  }
}

function toggleShowPassword() { showPassword.value = !showPassword.value }
function toggleShowConfirm() { showConfirm.value = !showConfirm.value }

function onSubmit(e: Event) {
  e.preventDefault()
  clientPasswordError.value = ''
  clientConfirmError.value = ''

  let valid = true
  if (newPassword.value.length < 6) {
    clientPasswordError.value = 'Password must be at least 6 characters.'
    showStrength.value = false
    valid = false
  }
  if (newPassword.value !== confirmPassword.value) {
    clientConfirmError.value = 'Passwords do not match.'
    valid = false
  }

  if (!valid) return

  // submit the native form
  const form = (e.target as HTMLFormElement)
  form.submit()
}

</script>
