<template>
  <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10 text-center">
      <div class="w-24 h-24 mx-auto bg-blue-100 flex items-center justify-center rounded-full mb-6">
        <Icon name="fa7-solid:envelope-open-text" class="text-blue-600 text-5xl" aria-hidden="true" />
      </div>

      <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Verify your email</h1>

      <p class="text-gray-600 text-base leading-relaxed">
        We sent a verification link to <span class="font-semibold text-blue-600">{{ email }}</span>.
      </p>

      <p class="mt-4 text-base text-gray-600">
        Please click the link in the email to complete your registration. Check your spam folder if you don’t see it.
      </p>

      <div class="mt-6 flex flex-col sm:flex-row gap-3 justify-center">
        <a href="/login"
          class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
          <Icon name="fa7-solid:sign-in-alt" class="mr-2" />
          Go to Login
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

<script setup lang="ts">
const email = useServerVar<string>('email', '')
</script>
