<template>
  <div class="bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="p-8">
      <div class="text-center mb-8">
        <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Verification Required</h1>
        <p class="text-gray-600 mt-2">For your security, please verify your identity to continue.</p>
      </div>

      <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
        <Icon name="fa-solid:exclamation-circle" class="mr-2" />
        {{ errorMsg }}
      </div>


      <form class="space-y-4" method="POST">
        <input type="hidden" name="cid" :value="challengeID">
        <button v-if="smsEnabled" type="submit" name="method" value="sms"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group">
          <Icon name="fa-solid:comment-sms" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">SMS OTP ({{ phone }})</span>
          <Icon name="fa-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <button v-if="emailEnabled" type="submit" name="method" value="email"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group">
          <Icon name="fa-solid:envelope" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">Email OTP ({{ email }})</span>
          <Icon name="fa-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <button v-if="totpEnabled" type="submit" name="method" value="totp"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group">
          <Icon name="fa-solid:mobile-screen" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">Authenticator App</span>
          <Icon name="fa-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>
      </form>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <form action="/logout" method="POST">
        <input type="hidden" name="_csrf" value="token">
        <button class="text-red-600 hover:text-red-500 text-sm font-medium" type="submit">
          Log out >>
        </button>
      </form>
    </footer>
  </div>
</template>

<script setup lang="ts">
const errorMsg = useServerVar<string>('errorMsg', '')
const challengeID = useServerVar<string>('challengeID', '')
const emailEnabled = useServerVar<boolean>('emailEnabled', false)
const smsEnabled = useServerVar<boolean>('smsEnabled', false)
const totpEnabled = useServerVar<boolean>('totpEnabled', false)
const phone = useServerVar<string>('phone', '')
const email = useServerVar<string>('email', '')
</script>
