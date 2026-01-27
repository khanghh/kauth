<template>
  <div class="bg-white rounded-xl shadow-lg overflow-hidden">
    <div class="p-8">
      <div class="text-center mb-8">
        <img src="/images/logo.png" alt="Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-2xl font-bold text-gray-800">Enter Verification Code</h1>
        <p class="text-gray-600 mt-2">Enter the 6-digit code from your authenticator app </p>
      </div>

      <form method="POST" class="space-y-6" id="otpForm">
        <input type="hidden" name="cid" :value="cid">
        <input type="hidden" name="code" :value="otpCode">

        <div class="flex justify-between gap-2">
          <input
            v-for="(_, idx) in otpDigits"
            :key="idx"
            ref="otpInputs"
            v-model="otpDigits[idx]"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            maxlength="1"
            class="otp-box w-12 h-12 border rounded-lg text-center text-xl focus:ring-2 focus:ring-blue-500 focus:outline-none"
            @keypress="onKeyPressDigit"
            @input="onInput(idx)"
            @keydown="onKeyDown($event, idx)"
            @paste="onPaste($event)" />
        </div>

        <div class="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
          <div class="flex">
            <div class="flex-shrink-0">
              <Icon name="fa7-solid:exclamation-triangle" class="text-yellow-500" />
            </div>
            <div class="ml-3">
              <h3 class="text-sm font-medium text-yellow-800">Trouble with your code?</h3>
              <div class="mt-2 text-sm text-yellow-700">
                <p>Make sure the time on your device is synchronized.</p>
              </div>
            </div>
          </div>
        </div>


        <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
          <Icon name="fa7-solid:exclamation-circle" class="mr-2" />
          {{ errorMsg }}
        </div>

        <button type="submit"
          class="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition">
          Verify
        </button>
      </form>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Need help? <a :href="contactLink" class="text-blue-600 hover:underline font-medium">Contact Support</a>
      </p>
    </footer>
  </div>
</template>

<script setup lang="ts">

const config = useRuntimeConfig().public
const contactLink = config.contactLink as string || '#'

const cid = useServerVar<string>('cid', '')
const errorMsg = useServerVar<string>('errorMsg', '')

const otpDigits = ref<string[]>(Array.from({ length: 6 }, () => ''))
const otpInputs = ref<HTMLInputElement[]>([])

const otpCode = computed(() => otpDigits.value.join(''))

const onKeyPressDigit = (e: KeyboardEvent) => {
  if (e.key.length === 1 && !/\d/.test(e.key)) {
    e.preventDefault()
  }
}

const focusIndex = (idx: number) => {
  otpInputs.value[idx]?.focus()
}

const onInput = (idx: number) => {
  const raw = otpDigits.value[idx] ?? ''
  const digit = raw.replace(/\D/g, '').slice(-1)
  otpDigits.value[idx] = digit

  if (digit && idx < otpDigits.value.length - 1) {
    focusIndex(idx + 1)
  }
}

const onKeyDown = (e: KeyboardEvent, idx: number) => {
  if (e.key === 'Backspace' && !otpDigits.value[idx] && idx > 0) {
    focusIndex(idx - 1)
  }
}

const onPaste = (e: ClipboardEvent) => {
  e.preventDefault()
  const pasteData = e.clipboardData?.getData('text') ?? ''
  if (!pasteData) return

  const digits = pasteData.replace(/\D/g, '').slice(0, otpDigits.value.length).split('')
  if (digits.length === 0) return

  otpDigits.value = otpDigits.value.map((_, i) => digits[i] ?? '')
  focusIndex(Math.min(digits.length, otpDigits.value.length) - 1)
}

</script>
