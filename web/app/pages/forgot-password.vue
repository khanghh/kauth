<script setup lang="ts">
const config = useRuntimeConfig()

const form = ref({
  username: '',
  email: ''
})

const emailSent = ref(false)
const isSubmitting = ref(false)

const errors = ref({
  username: '',
  email: '',
  general: ''
})

const validate = () => {
  let ok = true
  Object.keys(errors.value).forEach(k => errors.value[k as keyof typeof errors.value] = '')

  if (!form.value.username.trim()) {
    errors.value.username = 'Vui lòng nhập tên người dùng.'
    ok = false
  }

  if (!form.value.email.trim()) {
    errors.value.email = 'Vui lòng nhập địa chỉ email.'
    ok = false
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(form.value.email.trim())) {
    errors.value.email = 'Địa chỉ email không hợp lệ.'
    ok = false
  }

  return ok
}

const handleSubmit = async () => {
  if (!validate()) return
  isSubmitting.value = true
  errors.value.general = ''

  try {
    await $fetch('/api/forgot-password', {
      method: 'POST',
      body: form.value
    })
    emailSent.value = true
  } catch (err: any) {
    errors.value.general = err.data?.message || 'An error occurred while sending the request. Please try again.'
  } finally {
    isSubmitting.value = false
  }
}

useHead({
  title: 'Quên mật khẩu',
  script: [
    { src: 'https://challenges.cloudflare.com/turnstile/v0/api.js', defer: true }
  ]
})
</script>

<template>
  <div>
    <div class="px-6 sm:px-10 py-10">
      <div class="">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto mb-4 object-contain">

        <template v-if="emailSent">
          <div class="text-center mt-6">
            <div class="w-24 h-24 mx-auto bg-blue-100 flex items-center justify-center rounded-full mb-6">
              <Icon name="fa7-solid:envelope-open-text" class="text-blue-600 text-5xl" />
            </div>
            <h2 class="text-3xl font-bold text-gray-800 mb-4">Đã gửi liên kết khôi phục</h2>
            <p class="text-gray-600 mb-4">Chúng tôi đã gửi liên kết đặt lại mật khẩu tới email của bạn. Vui lòng kiểm
              tra hộp thư và làm theo hướng dẫn.</p>
            <div class="mt-6 flex flex-col sm:flex-row gap-3 justify-center">
              <NuxtLink to="/login"
                class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
                Đến trang đăng nhập</NuxtLink>
            </div>
          </div>
        </template>

        <template v-else>
          <div class="text-center mb-6">
            <h1 class="text-3xl font-bold text-gray-800 mb-4">Quên mật khẩu?</h1>
            <p class="text-gray-600 mt-2">Vui lòng nhập tên người dùng và email để đặt lại mật khẩu.</p>
          </div>

          <div v-if="errors.general"
            class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-center">
            <Icon name="fa7-solid:circle-exclamation" class="mr-2" />
            {{ errors.general }}
          </div>

          <form @submit.prevent="handleSubmit" class="space-y-6" novalidate>
            <div>
              <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Tên người dùng</label>
              <div class="relative">
                <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Icon name="fa7-solid:user" class="text-gray-400" />
                </span>
                <input id="username" v-model="form.username" type="text" required
                  class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                  placeholder="Nhập tên người dùng">
              </div>
              <p v-if="errors.username" class="mt-1 text-sm text-red-600">{{ errors.username }}</p>
            </div>

            <div>
              <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Địa chỉ email</label>
              <div class="relative">
                <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                  <Icon name="fa7-solid:envelope" class="text-gray-400" />
                </span>
                <input id="email" v-model="form.email" type="email" required
                  class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                  placeholder="Nhập địa chỉ email">
              </div>
              <p v-if="errors.email" class="mt-1 text-sm text-red-600">{{ errors.email }}</p>
            </div>

            <div v-if="config.public.turnstileSiteKey" class="cf-turnstile text-center"
              :data-sitekey="config.public.turnstileSiteKey"></div>

            <div class="pt-2">
              <button type="submit" :disabled="isSubmitting"
                class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center disabled:opacity-70 disabled:cursor-not-allowed">
                <Icon v-if="!isSubmitting" name="fa7-solid:paper-plane" class="mr-2" />
                <Icon v-else name="fa7-solid:spinner" class="mr-2 animate-spin" />
                {{ isSubmitting ? 'Đang gửi...' : 'Gửi liên kết khôi phục' }}
              </button>
            </div>

            <div class="text-center">
              <NuxtLink to="/login" class="text-blue-600 hover:underline font-medium">
                <Icon name="fa7-solid:arrow-left" class="mr-1" />
                Quay lại đăng nhập
              </NuxtLink>
            </div>
          </form>
        </template>
      </div>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Cần trợ giúp?
        <a href="#" class="text-blue-600 hover:underline font-medium">Liên hệ hỗ trợ</a>
      </p>
    </footer>
  </div>
</template>

<style scoped>
.form-input:focus {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}
</style>
