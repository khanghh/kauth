<script setup lang="ts">
import OtpInput from './OtpInput.vue'

const props = defineProps<{
  cid: string
  csrfToken: string
}>()

const emit = defineEmits<{
  (e: 'back'): void
}>()

const code = ref('')
const errorMsg = ref('')
const isLoading = ref(false)

const verifyOtp = async () => {
  if (code.value.length !== 6) {
    errorMsg.value = 'Vui lòng nhập đủ 6 số.'
    return
  }

  errorMsg.value = ''
  isLoading.value = true

  try {
    const res: any = await $fetch('', {
      method: 'POST',
      body: {
        cid: props.cid,
        _csrf: props.csrfToken,
        code: code.value
      }
    })

    if (res?.redirect) {
      window.location.href = res.redirect
    } else {
      window.location.reload()
    }
  } catch (err: any) {
    console.error(err)
    errorMsg.value = err.data?.message || 'Mã xác minh không chính xác.'
    code.value = ''
  } finally {
    isLoading.value = false
  }
}
</script>

<template>
  <div class="space-y-6">
    <div class="text-center mb-6">
      <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Nhập mã xác minh</h1>
      <p class="text-gray-600 mt-2">
        Nhập mã 6 chữ số từ ứng dụng xác thực của bạn (Authenticator).
      </p>
    </div>

    <!-- Error Message -->
    <div v-if="errorMsg"
      class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-start">
      <Icon name="fa7-solid:circle-exclamation" class="mr-2 mt-0.5 text-base" />
      <span>{{ errorMsg }}</span>
    </div>

    <OtpInput
      v-model="code"
      :error="!!errorMsg"
      :disabled="isLoading"
      @submit="verifyOtp" />

    <div class="bg-yellow-50 p-4 rounded-lg border border-yellow-200 flex items-start">
      <Icon name="fa7-solid:triangle-exclamation" class="text-yellow-500 mt-0.5 mr-2" />
      <div class="text-sm text-yellow-800">
        <h3 class="font-medium">Gặp sự cố với mã?</h3>
        <p class="mt-1">Hãy đảm bảo thời gian trên thiết bị của bạn được đồng bộ.</p>
      </div>
    </div>

    <button
      @click="verifyOtp"
      :disabled="isLoading || code.length !== 6"
      class="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center">
      <Icon v-if="isLoading" name="fa7-solid:spinner" class="animate-spin mr-2" />
      <span>Xác nhận</span>
    </button>

    <div class="text-center pt-2">
      <button @click="emit('back')" class="text-sm text-gray-500 hover:text-gray-700">
        Thử cách khác
      </button>
    </div>
  </div>
</template>
