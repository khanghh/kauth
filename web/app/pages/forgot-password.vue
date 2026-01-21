<template>
  <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10">
      <div v-if="emailSent" class="text-center mt-6">
        <div class="w-24 h-24 mx-auto bg-blue-100 flex items-center justify-center rounded-full mb-6">
          <Icon name="fa-solid:envelope-open-text" class="text-blue-600 text-5xl" aria-hidden="true" />
        </div>
        <h1 class="text-3xl font-bold text-gray-800 mb-4">Reset Link Sent</h1>
        <p class="text-gray-600 mb-4">
          We've sent a password reset link to your email address. Please check your inbox and follow the instructions.
        </p>
        <div class="mt-6 flex flex-col sm:flex-row gap-3 justify-center">
          <a href="/login"
            class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
            <Icon name="fa-solid:sign-in-alt" class="mr-2" />
            Go to Login
          </a>
        </div>
      </div>

      <div v-else>
        <div class="text-center mb-6">
          <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
          <h1 class="text-3xl font-bold text-gray-800 mb-4">Forgot Password?</h1>
          <p class="text-gray-600 mt-2">
            Enter your username and the email address associated with your account. We'll send you a link to reset your
            password.
          </p>
        </div>

        <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
          <Icon name="fa-solid:exclamation-circle" class="mr-2" />
          {{ errorMsg }}
        </div>

        <form method="POST" class="space-y-6">
          <div>
            <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <div class="relative">
              <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <Icon name="fa-solid:user" class="text-gray-400" />
              </span>
              <input type="text" id="username" name="username" required
                class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                placeholder="Enter your username">
            </div>
          </div>

          <div>
            <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email address</label>
            <div class="relative">
              <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <Icon name="fa-solid:envelope" class="text-gray-400" />
              </span>
              <input type="email" id="email" name="email" required
                class="form-input w-full pl-10 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                placeholder="Enter your email address">
            </div>
          </div>

          <div v-if="turnstileSiteKey" class="cf-turnstile text-center" :data-sitekey="turnstileSiteKey"></div>
          <div class="pt-2">
            <button type="submit"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center">
              <Icon name="fa-solid:paper-plane" class="mr-2" />
              Send Reset Link
            </button>
          </div>
          <div class="text-center">
            <a href="/login" class="text-blue-600 hover:underline font-medium">
              <Icon name="fa-solid:arrow-left" class="mr-1" />
              Back to Login
            </a>
          </div>
        </form>
      </div>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Need help? <a href="#" class="text-blue-600 hover:underline font-medium">Contact Support</a>
      </p>
    </footer>
  </div>
</template>

<script setup lang="ts">
const emailSent = useServerVar<boolean>('emailSent', false)
const errorMsg = useServerVar<string>('errorMsg', '')
const turnstileSiteKey = useServerVar<string>('turnstileSiteKey', '')
</script>
