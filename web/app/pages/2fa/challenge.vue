<script setup lang="ts">
const route = useRoute()

// State
const errorMsg = ref('')
const isLoading = ref(false)

// Data from query/props
const cid = computed(() => route.query.cid as string || '')
const email = computed(() => route.query.email as string || '')
const phone = computed(() => route.query.phone as string || '')
const csrfToken = computed(() => route.query._csrf as string || '')

// Mock enabled factors
const enabledFactors = ref([
  { type: 'email', target: 'm***@example.com', cooldown: 30 },
  { type: 'sms', target: '+84 *** *** 123', cooldown: 0 },
  { type: 'totp', target: '', cooldown: 0 }
])

const emailFactor = computed(() => enabledFactors.value.find(f => f.type === 'email'))
const smsFactor = computed(() => enabledFactors.value.find(f => f.type === 'sms'))
const totpFactor = computed(() => enabledFactors.value.find(f => f.type === 'totp'))

const selectMethod = async (method: string) => {
  errorMsg.value = ''
  isLoading.value = true

  try {
    await $fetch('', {
      method: 'POST',
      body: {
        cid: cid.value,
        _csrf: csrfToken.value,
        method: method
      }
    })

    // Navigate to verify page
    await navigateTo({
      path: `/2fa/verify/${method}`,
      query: {
        ...route.query
      }
    })
  } catch (err: any) {
    console.error(err)
    errorMsg.value = err.data?.message || err.message || 'Đã xảy ra lỗi khi gửi mã.'
  } finally {
    isLoading.value = false
  }
}

// Layout
useHead({
  title: 'Xác minh danh tính',
  bodyAttrs: {
    class: 'bg-gray-50'
  }
})
</script>

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
          v-if="emailFactor"
          @click="selectMethod('email')"
          :disabled="isLoading"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group disabled:opacity-50 disabled:cursor-not-allowed">
          <Icon name="fa7-solid:envelope" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">
            {{ emailFactor.target ? `Mã qua Email (${emailFactor.target})` : 'Mã qua Email' }}
          </span>
          <Icon name="fa7-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <!-- SMS Method -->
        <button
          v-if="smsFactor"
          @click="selectMethod('sms')"
          :disabled="isLoading"
          class="w-full flex items-center p-4 border rounded-lg hover:bg-gray-50 transition group disabled:opacity-50 disabled:cursor-not-allowed">
          <Icon name="fa7-solid:comment-sms" class="text-blue-600 text-xl mr-3" />
          <span class="text-gray-800 font-medium flex-1 text-left">
            {{ smsFactor.target ? `Mã qua tin nhắn SMS (${smsFactor.target})` : 'Mã qua tin nhắn SMS' }}
          </span>
          <Icon name="fa7-solid:angle-right" class="text-gray-400 group-hover:text-gray-600" />
        </button>

        <!-- TOTP Method -->
        <button
          v-if="totpFactor"
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
