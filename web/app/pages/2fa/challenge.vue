<template>
  <div>
    <div class="p-8">

      <!-- Header Section -->
      <div class="text-center mb-6">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Yêu cầu xác minh</h1>
        <p class="text-gray-600 mt-2">Vì lý do bảo mật, vui lòng xác minh danh tính của bạn để tiếp tục.</p>
      </div>

      <!-- Error Message -->
      <div v-if="errorMsg"
        class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-start">
        <Icon name="fa7-solid:circle-exclamation" class="mr-2 mt-0.5 text-base" />
        <span>{{ errorMsg }}</span>
      </div>

      <!-- Selection Buttons -->
      <div class="space-y-4">
        <!-- Email Method -->
        <button
          v-if="emailEnabled"
          @click="selectMethod('email')"
          :disabled="isLoading"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group disabled:opacity-50 disabled:cursor-not-allowed">
          <Icon name="fa7-solid:envelope" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">
            Mã qua Email ({{ email }})
          </span>
          <Icon name="fa7-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <!-- SMS Method -->
        <button
          v-if="smsEnabled"
          @click="selectMethod('sms')"
          :disabled="isLoading"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group disabled:opacity-50 disabled:cursor-not-allowed">
          <Icon name="fa7-solid:comment-sms" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">
            Mã qua tin nhắn SMS ({{ phone }})
          </span>
          <Icon name="fa7-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <!-- TOTP Method -->
        <button
          v-if="totpEnabled"
          @click="selectMethod('totp')"
          :disabled="isLoading"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group disabled:opacity-50 disabled:cursor-not-allowed">
          <Icon name="fa7-solid:mobile-screen" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">
            Ứng dụng xác thực (Authenticator)
          </span>
          <Icon name="fa7-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>
      </div>

    </div>

    <!-- Footer -->
    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <form action="/logout" method="POST">
        <input type="hidden" name="_csrf" :value="csrfToken" />
        <button type="submit"
          class="text-red-600 hover:text-red-500 text-sm font-medium flex items-center justify-center gap-1 mx-auto">
          <span>Đăng xuất</span>
          <Icon name="fa7-solid:right-from-bracket" />
        </button>
      </form>
    </footer>
  </div>
</template>

<script setup lang="ts">
const route = useRoute()

// State
const isLoading = ref(false)

const email = useServerVar<string>('emailEnabled', '')
const emailEnabled = useServerVar<boolean>('emailEnabled', false)
const phone = useServerVar<string>('phone', '')
const smsEnabled = useServerVar<boolean>('smsEnabled', false)
const totpEnabled = useServerVar<boolean>('totpEnabled', false)
const errorMsg = useServerVar<string>('errorMsg', '')

const csrfToken = computed(() => route.query._csrf as string || '')

const selectMethod = async (method: string) => {
  errorMsg.value = ''
  isLoading.value = true
}

// Layout
useHead({
  title: 'Xác minh danh tính',
  bodyAttrs: {
    class: 'bg-gray-50'
  }
})
</script>
