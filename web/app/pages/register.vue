<template>
  <div>
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Tạo tài khoản</h1>
        <p class="text-gray-600 mt-2">Vui lòng điền thông tin bên dưới để tạo tài khoản</p>
      </div>
      <div v-if="errors.general"
        class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-center">
        <Icon name="fa7-solid:circle-exclamation" class="mr-2" />
        {{ errors.general }}
      </div>

      <form @submit.prevent="handleSubmit" class="space-y-6" novalidate>
        <div>
          <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Chọn tên người dùng</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:user" class="text-gray-400" />
            </span>
            <input
              id="username"
              v-model="form.username"
              type="text"
              name="username"
              autocomplete="username"
              required
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Nhập tên người dùng"
              :class="{ 'border-red-300 focus:border-red-500 focus:ring-red-200': errors.username }">
          </div>
          <p v-if="errors.username" class="mt-1 text-sm text-red-600">{{ errors.username }}</p>
        </div>

        <div>
          <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:envelope" class="text-gray-400" />
            </span>
            <input
              id="email"
              v-model="form.email"
              type="text"
              name="email"
              required
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Nhập địa chỉ email"
              :class="{ 'border-red-300 focus:border-red-500 focus:ring-red-200': errors.email }">
          </div>
          <p v-if="errors.email" class="mt-1 text-sm text-red-600">{{ errors.email }}</p>
        </div>

        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Tạo mật khẩu</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:lock" class="text-gray-400" />
            </span>
            <input
              id="password"
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              name="password"
              autocomplete="new-password"
              required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Tạo mật khẩu an toàn"
              :class="{ 'border-red-300 focus:border-red-500 focus:ring-red-200': errors.password }">
            <span
              class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 cursor-pointer hover:text-blue-600"
              @click="showPassword = !showPassword">
              <Icon :name="showPassword ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
            </span>
          </div>

          <div v-show="form.password" class="mt-2" id="passwordStrengthContainer">
            <div class="flex bg-gray-200 rounded-full overflow-hidden h-1.5">
              <div class="strength-bar" :class="strengthClass" :style="{ width: strengthWidth }"></div>
            </div>
            <p class="text-xs mt-1 transition-colors duration-200" :class="strengthTextClass">Độ mạnh mật khẩu: {{
              strengthLabel }}</p>
          </div>
          <p v-if="errors.password" class="mt-1 text-sm text-red-600">{{ errors.password }}</p>
        </div>

        <div>
          <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-1">Xác nhận mật khẩu</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:lock" class="text-gray-400" />
            </span>
            <input
              id="confirm_password"
              v-model="form.confirmPassword"
              :type="showConfirmPassword ? 'text' : 'password'"
              name="confirm_password"
              autocomplete="new-password"
              required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Xác nhận mật khẩu"
              :class="{ 'border-red-300 focus:border-red-500 focus:ring-red-200': errors.confirmPassword }">
            <span
              class="password-toggle absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 cursor-pointer hover:text-blue-600"
              @click="showConfirmPassword = !showConfirmPassword">
              <Icon :name="showConfirmPassword ? 'fa7-solid:eye-slash' : 'fa7-solid:eye'" />
            </span>
          </div>
          <p v-if="errors.confirmPassword" class="mt-1 text-sm text-red-600">{{ errors.confirmPassword }}</p>
        </div>

        <div class="flex items-start">
          <div class="flex items-center h-5">
            <input
              id="terms"
              v-model="form.terms"
              name="terms"
              type="checkbox"
              required
              class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded">
          </div>
          <div class="ml-3 text-sm">
            <label for="terms" class="font-medium text-gray-700">Tôi đồng ý với <NuxtLink to="#"
                class="text-blue-600 hover:text-blue-500">Điều khoản dịch vụ</NuxtLink> và <NuxtLink to="#"
                class="text-blue-600 hover:text-blue-500">Chính sách bảo mật</NuxtLink></label>
            <p v-if="errors.terms" class="mt-1 text-red-600 text-sm">{{ errors.terms }}</p>
          </div>
        </div>

        <div v-if="config.public.turnstileSiteKey" class="cf-turnstile text-center"
          :data-sitekey="config.public.turnstileSiteKey"></div>

        <div class="pt-2">
          <button type="submit"
            class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 w-full flex items-center justify-center disabled:opacity-70 disabled:cursor-not-allowed"
            :disabled="isSubmitting">
            <Icon v-if="!isSubmitting" name="fa7-solid:user-plus" class="mr-2" />
            <Icon v-else name="fa7-solid:spinner" class="mr-2 animate-spin" />
            {{ isSubmitting ? 'Đang tạo tài khoản...' : 'Tạo tài khoản' }}
          </button>
        </div>

      </form>
    </div>
    <div class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-600 text-sm">
        Bạn đã có tài khoản?
        <NuxtLink to="/login" class="text-blue-600 hover:text-blue-500 font-medium">Đăng nhập</NuxtLink>
      </p>
    </div>
  </div>
</template>

<style scoped>
.form-input:focus {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}

.strength-bar {
  height: 5px;
  border-radius: 3px;
  transition: width 0.3s, background-color 0.3s;
}

.strength-weak {
  background-color: #ef4444;
}

.strength-medium {
  background-color: #f59e0b;
}

.strength-strong {
  background-color: #10b981;
}
</style>

<script setup lang="ts">
const config = useRuntimeConfig()

const form = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  terms: false
})

const errors = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  terms: '',
  general: ''
})

const showPassword = ref(false)
const showConfirmPassword = ref(false)
const isSubmitting = ref(false)

// Password Strength
const passwordStrength = computed(() => {
  const password = form.value.password || ''
  let strength = 0
  if (password.length >= 8) strength++
  if (/[a-z]/.test(password)) strength++
  if (/[A-Z]/.test(password)) strength++
  if (/[0-9]/.test(password)) strength++
  if (/[^A-Za-z0-9]/.test(password)) strength++
  return strength
})

const strengthLabel = computed(() => {
  if (!form.value.password) return 'Nhập mật khẩu'
  if (passwordStrength.value <= 2) return 'Yếu'
  if (passwordStrength.value <= 4) return 'Trung bình'
  return 'Mạnh'
})

const strengthClass = computed(() => {
  if (passwordStrength.value <= 2) return 'strength-weak'
  if (passwordStrength.value <= 4) return 'strength-medium'
  return 'strength-strong'
})

const strengthWidth = computed(() => {
  if (!form.value.password) return '0%'
  if (passwordStrength.value <= 2) return '33%'
  if (passwordStrength.value <= 4) return '66%'
  return '100%'
})

const strengthTextClass = computed(() => {
  if (!form.value.password) return 'text-gray-500'
  if (passwordStrength.value <= 2) return 'text-red-500'
  if (passwordStrength.value <= 4) return 'text-yellow-500'
  return 'text-green-500'
})

const validate = () => {
  let isValid = true
  // Reset errors
  Object.keys(errors.value).forEach(key => errors.value[key as keyof typeof errors.value] = '')

  // Username check
  const username = form.value.username.trim()
  if (!username) {
    errors.value.username = 'Vui lòng nhập tên người dùng.'
    isValid = false
  } else if (!/^[A-Za-z]/.test(username)) {
    errors.value.username = 'Tên người dùng phải bắt đầu bằng chữ cái.'
    isValid = false
  } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.value.username = 'Tên người dùng chỉ được chứa chữ cái, số và dấu gạch dưới.'
    isValid = false
  }

  // Email check
  const email = form.value.email.trim()
  if (!email) {
    errors.value.email = 'Vui lòng nhập địa chỉ email.'
    isValid = false
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    errors.value.email = 'Địa chỉ email không hợp lệ.'
    isValid = false
  }

  // Password check
  if (form.value.password.length < 6) {
    errors.value.password = 'Mật khẩu phải có ít nhất 6 ký tự.'
    isValid = false
  }

  // Confirm password check
  if (form.value.password !== form.value.confirmPassword) {
    errors.value.confirmPassword = 'Mật khẩu không khớp.'
    isValid = false
  }

  // Terms check
  if (!form.value.terms) {
    errors.value.terms = 'Bạn phải đồng ý với Điều khoản để tiếp tục.'
    isValid = false
  }

  return isValid
}

const handleSubmit = async () => {
  if (!validate()) return

  isSubmitting.value = true
  errors.value.general = ''

  try {
    await $fetch('/api/register', {
      method: 'POST',
      body: form.value
    })
    // Redirect on success
    navigateTo('/login?registered=true')
  } catch (err: any) {
    errors.value.general = err.data?.message || 'Đã có lỗi xảy ra khi đăng ký.'
  } finally {
    isSubmitting.value = false
  }
}

useHead({
  title: useSiteTitle("Tạo tài khoản"),
  script: [
    { src: 'https://challenges.cloudflare.com/turnstile/v0/api.js', defer: true }
  ]
})
</script>
