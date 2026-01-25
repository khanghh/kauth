<template>
  <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <template v-if="oauthProvider">
          <div class="flex justify-center mb-4">
            <img v-if="picture" :src="picture" alt="Profile"
              class="avatar w-20 h-20 rounded-full border-4 border-blue-100 object-cover">
            <div v-else
              class="avatar w-20 h-20 rounded-full border-4 border-blue-100 bg-indigo-600 flex items-center justify-center text-white text-3xl font-bold">
              {{ (fullName?.[0] || 'U').toUpperCase() }}
            </div>
          </div>
          <h1 class="text-3xl font-bold text-gray-800 mb-2">Welcome, {{ fullName }}</h1>
          <p class="text-gray-600 mt-1">{{ email }}</p>
          <div class="mt-3 inline-flex items-center bg-blue-50 text-blue-700 text-sm px-3 py-1 rounded-full">
            <Icon name="fa7-solid:check-circle" class="mr-1" />
            Connected via &nbsp; <span class="capitalize">{{ oauthProvider }}</span>
          </div>
          <p class="text-gray-600 mt-4">Set a username and password to continue</p>
        </template>
        <template v-else>
          <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
          <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Create your account</h1>
          <p class="text-gray-600 mt-2">Fill out the form to create your account</p>
        </template>
      </div>

      <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
        <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
        {{ errorMsg }}
      </div>

      <form ref="formEl" class="space-y-6" method="POST" novalidate @submit="onSubmit">
        <div>
          <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Choose a username</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:user" class="text-gray-400" />
            </span>
            <input type="text" id="username" name="username" autocomplete="username" required
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Enter your username" v-model="username">
          </div>
          <p :class="['mt-1 text-sm text-red-600', { hidden: !usernameError }]">{{ usernameError }}
          </p>
        </div>

        <div v-if="!oauthProvider">
          <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email address</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:envelope" class="text-gray-400" />
            </span>
            <input type="text" id="email" name="email" required
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Enter your email address" v-model="email">
          </div>
          <p :class="['mt-1 text-sm text-red-600', { hidden: !emailError }]">{{ emailError }}</p>
        </div>

        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Create password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:lock" class="text-gray-400" />
            </span>
            <input :type="showPassword ? 'text' : 'password'" id="password" name="password" autocomplete="new-password"
              required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Create a secure password" v-model="password">
            <button class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
              type="button"
              tabindex="-1" @click="showPassword = !showPassword" aria-label="Toggle password visibility">
              <Icon :name="showPassword ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
            </button>
          </div>

          <div class="mt-2" :class="{ hidden: !showStrength }">
            <div class="flex bg-gray-200 rounded-full overflow-hidden h-1.5">
              <div class="strength-bar" :class="strengthBarClass"></div>
            </div>
            <p class="text-xs mt-1" :class="strengthTextClass">{{ strengthText }}</p>
          </div>
          <p :class="['mt-1 text-sm text-red-600', { hidden: !passwordError }]">{{ passwordError }}
          </p>
        </div>

        <div>
          <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-1">Confirm password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:lock" class="text-gray-400" />
            </span>
            <input :type="showConfirmPassword ? 'text' : 'password'" id="confirm_password" name="confirm_password"
              autocomplete="new-password" required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Confirm your password" v-model="confirmPassword">
            <button class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500"
              type="button"
              tabindex="-1" @click="showConfirmPassword = !showConfirmPassword"
              aria-label="Toggle confirm password visibility">
              <Icon :name="showConfirmPassword ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
            </button>
          </div>
          <p :class="['mt-1 text-sm text-red-600', { hidden: !confirmPasswordError }]">{{ confirmPasswordError
          }}</p>
        </div>

        <div class="flex items-start">
          <div class="flex items-center h-5">
            <input id="terms" name="terms" type="checkbox" required
              class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded" v-model="termsAccepted">
          </div>
          <div class="ml-3 text-sm">
            <label for="terms" class="font-medium text-gray-700">I agree to the <a href="/terms"
                class="text-blue-600 hover:text-blue-500">Terms of Service</a> and <a href="/privacy"
                class="text-blue-600 hover:text-blue-500">Privacy Policy</a></label>
            <p :class="['mt-1 text-red-600', { hidden: !termsError }]">{{ termsError }}</p>
          </div>
        </div>

        <div v-if="turnstileSiteKey" class="cf-turnstile text-center" :data-sitekey="turnstileSiteKey"></div>
        <div class="pt-2">
          <button type="submit"
            class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 w-full flex items-center justify-center">
            <Icon name="fa7-solid:user-plus" class="mr-2" />
            {{ oauthProvider ? 'Complete Registration' : 'Create Account' }}
          </button>
        </div>

        <div v-if="oauthProvider" class="text-center mt-4">
          <a href="/login?renew=true" class="text-sm text-blue-600 hover:underline flex items-center justify-center">
            <Icon name="fa7-solid:right-to-bracket" class="mr-2" />
            Sign in with another account
          </a>
        </div>

      </form>
    </div>
    <div v-if="!oauthProvider" class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-600 text-sm">
        Already have an account?
        <a href="/login" class="text-blue-600 hover:text-blue-500 font-medium">Sign in</a>
      </p>
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
const config = useRuntimeConfig().public
const turnstileSiteKey = config.turnstileSiteKey

const oauthProvider = useServerVar<string>('oauthProvider', '')
const email = useServerVar<string>('email', '')
const picture = useServerVar<string>('picture', '')
const fullName = useServerVar<string>('fullName', '')
const username = useServerVar<string>('username', '')

const errorMsg = useServerVar<string>('errorMsg', '')
const usernameError = useServerVar<string>('usernameError', '')
const emailError = useServerVar<string>('emailError', '')
const passwordError = useServerVar<string>('passwordError', '')

const formEl = ref<HTMLFormElement | null>(null)

const password = ref('')
const confirmPassword = ref('')
const termsAccepted = ref(false)

const confirmPasswordError = ref('')
const termsError = ref('')

const clearClientErrors = () => {
  usernameError.value = ''
  emailError.value = ''
  passwordError.value = ''
  confirmPasswordError.value = ''
  termsError.value = ''
}

const showPassword = ref(false)
const showConfirmPassword = ref(false)

const strengthScore = computed(() => {
  const pwd = password.value
  let score = 0
  if (pwd.length >= 8) score++
  if (/[a-z]/.test(pwd)) score++
  if (/[A-Z]/.test(pwd)) score++
  if (/[0-9]/.test(pwd)) score++
  if (/[^A-Za-z0-9]/.test(pwd)) score++
  return score
})

const showStrength = computed(() => password.value.length > 0 && passwordError.value === '')

const strengthText = computed(() => {
  if (password.value.length === 0) return 'Enter a password'
  const base = 'Password strength: '
  if (strengthScore.value <= 2) return base + 'Weak'
  if (strengthScore.value <= 4) return base + 'Medium'
  return base + 'Strong'
})

const strengthBarClass = computed(() => {
  if (password.value.length === 0) return ''
  if (strengthScore.value <= 2) return 'strength-weak'
  if (strengthScore.value <= 4) return 'strength-medium'
  return 'strength-strong'
})

const strengthTextClass = computed(() => {
  if (password.value.length === 0) return 'text-gray-500'
  if (strengthScore.value <= 2) return 'text-red-500'
  if (strengthScore.value <= 4) return 'text-yellow-500'
  return 'text-green-500'
})

const validate = () => {
  clearClientErrors()
  let valid = true

  const u = username.value.trim()
  if (!u) {
    usernameError.value = 'Username is required.'
    valid = false
  } else if (!/^[A-Za-z]/.test(u)) {
    usernameError.value = 'Username must start with a letter.'
    valid = false
  } else if (!/^[a-zA-Z0-9_]+$/.test(u)) {
    usernameError.value = 'Username can only contain letters, numbers, and underscores.'
    valid = false
  }

  if (!oauthProvider.value) {
    const e = email.value?.trim()
    if (!e) {
      emailError.value = 'Email address is required.'
      valid = false
    } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(e)) {
      emailError.value = 'Invalid email address.'
      valid = false
    }
  }

  if (password.value.length < 6) {
    passwordError.value = 'Password must be at least 6 characters.'
    valid = false
  }

  if (password.value !== confirmPassword.value) {
    confirmPasswordError.value = 'Passwords do not match.'
    valid = false
  }

  if (!termsAccepted.value) {
    termsError.value = 'You must agree to the terms to continue.'
    valid = false
  }

  return valid
}

const onSubmit = (e: Event) => {
  if (!validate()) {
    e.preventDefault()
    return
  }

  formEl.value?.submit()
}


useHead({
  title: useSiteTitle('Create Your Account'),
  script: [
    {
      src: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
      defer: true
    }
  ]
})
</script>
