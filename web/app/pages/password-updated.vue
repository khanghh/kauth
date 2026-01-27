<template>
  <main class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10 text-center">

      <div class="w-24 h-24 mx-auto bg-green-100 flex items-center justify-center rounded-full mb-4">
        <Icon name="fa7-solid:circle-check" class="text-green-500 text-5xl" aria-hidden="true" />
      </div>
      <h1 class="text-3xl font-bold text-gray-800 mb-4">Password Updated</h1>
      <p class="text-gray-600 mt-2">
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

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Need help? <a :href="contactLink" class="text-blue-600 hover:underline font-medium">Contact Support</a>
      </p>
    </footer>
  </main>
</template>

<script setup lang="ts">
const config = useRuntimeConfig().public
const contactLink = config.contactLink as string || '#'
</script>
