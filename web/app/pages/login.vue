<template>
  <div class="shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Welcome back</h1>
        <p class="text-gray-600 mt-2">Sign in to your account</p>
      </div>

      <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
        <Icon name="fa-solid:exclamation-circle" class="mr-2" />
        {{ errorMsg }}
      </div>

      <form class="space-y-6" method="POST">
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Username or email</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa-solid:user" />
            </span>
            <input tabindex="1" type="text" name="username" required
              class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Your username or email address" :value="identifier">
          </div>
        </div>

        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
              <Icon name="fa-solid:lock" />
            </span>
            <input tabindex="2" type="password" id="password" name="password" autocomplete="new-password" required
              class="form-input w-full pl-10 pr-10 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
              placeholder="Enter your password">
          </div>
          <div class="flex justify-end mt-1">
            <a href="/forgot-password" class="text-sm text-blue-600 hover:text-blue-500">Forgot password?</a>
          </div>
        </div>

        <div v-if="turnstileSiteKey" class="cf-turnstile text-center" :data-sitekey="turnstileSiteKey"></div>
        <button tabindex="3" type="submit"
          class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
          Sign in
        </button>
      </form>

      <div class="flex items-center my-6">
        <div class="flex-grow border-t border-gray-300"></div>
        <span class="mx-4 text-gray-500 text-sm">or sign in with</span>
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
          <Icon name="fa7-brands:facebook" class="text-white text-lg" />
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
        Don't have an account?
        <a href="/register" class="text-blue-600 hover:text-blue-500 font-medium">Sign up</a>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
const errorMsg = useServerVar<string>('errorMsg', '')
const identifier = useServerVar<string>('identifier', '')
const turnstileSiteKey = useServerVar<string>('turnstileSiteKey', '{{.turnstileSiteKey}}')

const googleOAuthURL = useServerVar<string>('googleOAuthURL', '{{.googleOAuthURL}}')
const facebookOAuthURL = useServerVar<string>('facebookOAuthURL', '{{.facebookOAuthURL}}')
const discordOAuthURL = useServerVar<string>('discordOAuthURL', '{{.discordOAuthURL}}')
const microsoftOAuthURL = useServerVar<string>('microsoftOAuthURL', '{{.microsoftOAuthURL}}')
const appleOAuthURL = useServerVar<string>('appleOAuthURL', '{{.appleOAuthURL}}')

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
