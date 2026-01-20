<template>
  <div>
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Chào mừng trở lại</h1>
        <p class="text-gray-600 mt-2">Vui lòng đăng nhập để tiếp </p>
      </div>

      <div v-if="errorMsg"
        class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-center">
        <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
        {{ errorMsg }}
      </div>

      <form class="space-y-6" @submit.prevent="handleLogin">
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Tên đăng nhập hoặc email</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:user" />
            </span>
            <input
              tabindex="1"
              type="text"
              name="username"
              required
              v-model="identifier"
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Tên đăng nhập hoặc địa chỉ email của bạn">
          </div>
        </div>

        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Mật khẩu</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa7-solid:lock" />
            </span>
            <input
              tabindex="2"
              type="password"
              id="password"
              name="password"
              autocomplete="new-password"
              required
              v-model="password"
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Nhập mật khẩu của bạn">
          </div>
          <div class="flex justify-end mt-1">
            <NuxtLink to="/forgot-password" class="text-sm text-blue-600 hover:text-blue-500">Quên mật khẩu?
            </NuxtLink>
          </div>
        </div>

        <input type="hidden" name="_csrf" :value="csrfToken">

        <div v-if="turnstileSiteKey" class="cf-turnstile text-center" :data-sitekey="turnstileSiteKey"></div>

        <button tabindex="3" type="submit"
          class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
          Đăng nhập
        </button>
      </form>

      <div class="flex items-center my-6">
        <div class="flex-grow border-t border-gray-300"></div>
        <span class="mx-4 text-gray-500 text-sm">hoặc đăng nhập bằng</span>
        <div class="flex-grow border-t border-gray-300"></div>
      </div>

      <div class="flex justify-center space-x-4">
        <a v-if="googleOAuthURL" :href="googleOAuthURL"
          class="w-10 h-10 rounded-full bg-[#EA4335] flex items-center justify-center hover:shadow-md transition duration-200"
          title="Sign in with Google">
          <Icon name="fa7-brands:google" class="text-white text-lg" />
        </a>

        <a v-if="facebookOAuthURL" :href="facebookOAuthURL"
          class="w-10 h-10 rounded-full bg-[#1877F2] flex items-center justify-center hover:shadow-md transition duration-200"
          title="Sign in with Facebook">
          <Icon name="fa7-brands:facebook-f" class="text-white text-lg" />
        </a>

        <a v-if="discordOAuthURL" :href="discordOAuthURL"
          class="w-10 h-10 rounded-full flex items-center justify-center hover:shadow-md transition duration-200"
          style="background-color: #5865F2;"
          title="Sign in with Discord">
          <Icon name="fa7-brands:discord" class="text-white text-lg" />
        </a>

        <a v-if="microsoftOAuthURL" :href="microsoftOAuthURL"
          class="w-10 h-10 rounded-full flex items-center justify-center hover:shadow-md transition duration-200"
          style="background-color: #0078D4;"
          title="Sign in with Microsoft">
          <Icon name="fa7-brands:microsoft" class="text-white text-lg" />
        </a>

        <a v-if="appleOAuthURL" :href="appleOAuthURL"
          class="w-10 h-10 rounded-full bg-black flex items-center justify-center hover:shadow-md transition duration-200"
          title="Sign in with Apple">
          <Icon name="fa7-brands:apple" class="text-white text-lg" />
        </a>
      </div>
    </div>

    <div class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-600 text-sm">
        Chưa có tài khoản?
        <NuxtLink to="/register" class="text-blue-600 hover:text-blue-500 font-medium">Đăng ký</NuxtLink>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">

const errorMsg = ref('')
const identifier = ref('')
const password = ref('')
const turnstileSiteKey = ref('')
const csrfToken = ref('')

// Initialize with example values for UI demonstration or fetch from config/API
const googleOAuthURL = ref('#')
const facebookOAuthURL = ref('#')
const discordOAuthURL = ref('#')
const microsoftOAuthURL = ref('#')
const appleOAuthURL = ref('#')

const handleLogin = () => {
  // TODO: Implement login logic
  console.log('Login attempt', identifier.value)
}

useHead({
  title: useSiteTitle('Đăng nhập'),
  bodyAttrs: {
    class: 'bg-gray-50'
  },
  script: [
    {
      src: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
      defer: true
    }
  ]
})
</script>

<style scoped>
.form-input:focus {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
}
</style>
