<script setup lang="ts">
import OtpInput from './OtpInput.vue'

const props = defineProps<{
  cid: string
  csrfToken: string
  phone: string
}>()

const emit = defineEmits<{
  (e: 'back'): void
}>()

const code = ref('')
const errorMsg = ref('')
const isLoading = ref(false)
const countdown = ref(60)
let timerInterval: NodeJS.Timeout | null = null

const startTimer = () => {
  countdown.value = 60
  if (timerInterval) clearInterval(timerInterval)
  timerInterval = setInterval(() => {
    countdown.value--
    if (countdown.value <= 0 && timerInterval) {
      clearInterval(timerInterval)
    }
  }, 1000)
}

const sendCode = async () => {
  isLoading.value = true
  try {
    await $fetch('', {
      method: 'POST',
      body: {
        cid: props.cid,
        _csrf: props.csrfToken,
        method: 'sms'
      }
    })
    startTimer()
  } catch (err: any) {
    console.error(err)
    errorMsg.value = err.data?.message || 'Không thể gửi mã. Vui lòng thử lại.'
  } finally {
    isLoading.value = false
  }
}

const resendCode = async () => {
  if (countdown.value > 0) return
  errorMsg.value = ''
  await sendCode()
}

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

onMounted(() => {
  startTimer()
})

onUnmounted(() => {
  if (timerInterval) clearInterval(timerInterval)
})
</script>

<template>
  <div class="space-y-6">
    <div class="text-center mb-6">
      <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Nhập mã xác minh</h1>
      <p class="text-gray-600 mt-2">
        Chúng tôi đã gửi mã đến số điện thoại <span class="font-bold">{{ phone }}</span>
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

    <div class="flex justify-between items-center text-sm">
      <span class="text-gray-600">Bạn không nhận được mã?</span>
      <button
        type="button"
        @click="resendCode"
        :disabled="countdown > 0 || isLoading"
        class="flex items-center">
        <span
          class="font-medium"
          :class="countdown > 0 ? 'text-gray-400' : 'text-blue-600 hover:text-blue-500 hover:underline'">
          Gửi lại
        </span>
        <span v-if="countdown > 0" class="text-gray-500 ml-1">trong {{ countdown }}s</span>
      </button>
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
