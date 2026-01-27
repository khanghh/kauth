<template>
  <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="p-8">
      <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
      <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Authorize Access</h1>
      <p class="text-lg text-gray-600 mb-6 leading-relaxed text-center">
        Confirm you want to sign in to <span class="font-semibold text-blue-600">{{ serviceName }}</span> as
        <span class="font-semibold text-blue-600">{{ email }}</span>
      </p>

      <div class="bg-gray-50 rounded-lg p-4 mb-6 border border-gray-200">
        <div class="flex items-center mb-3">
          <div class="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mr-3">
            <Icon name="fa7-solid:globe" class="text-blue-600" />
          </div>
          <div>
            <p class="font-medium text-gray-800">{{ serviceName }}</p>
            <p class="text-sm text-gray-600 truncate">{{ serviceURL }}</p>
          </div>
        </div>
        <div class="text-sm text-gray-600">
          <p>This application is requesting permission to:</p>
          <ul class="mt-2 space-y-1">
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="text-green-500 mt-0.5 mr-2" />
              <span>Access your basic profile information</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="text-green-500 mt-0.5 mr-2" />
              <span>View your email address</span>
            </li>
          </ul>
        </div>
      </div>

      <form method="post">
        <div class="flex flex-row gap-3">
          <a href="/"
            class="flex-1 px-5 py-3 border border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition flex items-center justify-center gap-2">
            <Icon name="fa7-solid:xmark" />
            Cancel
          </a>
          <button type="submit" name="confirm" value="true"
            class="flex-1 px-5 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition flex items-center justify-center gap-2 shadow-sm">
            <Icon name="fa7-solid:check" />
            Confirm
          </button>
        </div>
      </form>

      <div class="mt-6 pt-6 border-t border-gray-200">
        <p class="mt-4 text-xs text-gray-400 text-center">
          By authorizing, you agree to our
          <a href="#" class="text-blue-500 hover:underline">Terms of Service</a> and
          <a href="#" class="text-blue-500 hover:underline">Privacy Policy</a>
        </p>
      </div>
    </div>
    <div class="bg-gray-50 px-8 py-4 text-center">
      <form action="/logout" method="POST">
        <button class="text-red-600 hover:text-red-500 text-sm font-medium" type="submit">
          Log out >>
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
const serviceName = useServerVar<string>('serviceName', '')
const email = useServerVar<string>('email', '')
const serviceURL = useServerVar<string>('serviceURL', '')
</script>
