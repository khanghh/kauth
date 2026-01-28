<template>
  <div class="max-w-4xl mx-auto">
    <div class="mb-8">
      <div class="flex items-center mb-2">
        <NuxtLink
          to="/two-factor"
          aria-label="Back"
          class="md:hidden flex items-center mr-2">
          <Icon name="fa7-solid:arrow-left" class="text-gray-700 w-8 h-8" />
        </NuxtLink>
        <h1 class="text-2xl font-bold text-gray-800 leading-none">
          Setup Authenticator App
        </h1>
      </div>
      <p class="text-gray-600">
        Use an authenticator app to generate secure, one-time codes.
      </p>
    </div>
    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
      <div class="flex items-center justify-between">
        <h2 class="text-lg font-semibold text-gray-800">Setup Authenticator App</h2>
      </div>

      <div class="py-6">
        <div id="enrollmentFlow">
          <div class="step-indicator">
            <div
              v-for="i in 4"
              :key="i"
              class="step-item"
              :class="{
                'step-active': currentStep === i,
                'step-completed': currentStep > i,
                'step-inactive': currentStep < i
              }">
              <div class="step-number">
                <Icon v-if="currentStep > i" name="fa7-solid:check" />
                <template v-else>{{ i }}</template>
              </div>
              <span class="step-label">{{ stepLabels[i - 1] }}</span>
            </div>
          </div>

          <!-- Step 1: App Setup -->
          <div v-show="currentStep === 1" class="step-container">
            <div class="mb-8">
              <p class="text-gray-600 text-center mb-6">
                Install an authenticator app if you don’t already have one.
              </p>

              <div class="bg-gray-50 p-6 rounded-lg mb-6">
                <h4 class="font-medium text-gray-800 mb-4 text-center">Recommended Apps</h4>
                <div class="app-icons">
                  <div class="app-icon text-blue-500">
                    <img src="/images/google_authenticator.png" alt="Google Authenticator"
                      class="w-12 h-12 object-contain" />
                  </div>
                  <div class="app-icon text-purple-600">
                    <img src="/images/microsoft_authenticator.png" alt="Microsoft Authenticator"
                      class="w-12 h-12 object-contain" />
                  </div>
                  <div class="app-icon text-red-500">
                    <Icon name="fa7-solid:mobile-alt" class="text-2xl" />
                  </div>
                </div>
                <p class="text-center text-gray-600 text-sm mt-4">
                  Google Authenticator, Microsoft Authenticator or any TOTP-compatible app
                </p>
              </div>

              <div class="bg-blue-50 p-4 rounded-lg">
                <div class="flex">
                  <div class="flex-shrink-0">
                    <Icon name="fa7-solid:info-circle" class="text-blue-500 mt-1" />
                  </div>
                  <div class="ml-3">
                    <h3 class="text-sm font-medium text-blue-800">How it works</h3>
                    <div class="mt-2 text-sm text-blue-700">
                      <p>After enrolling, you’ll be able to use your authenticator app to verify your identity during
                        sign-in or sensitive actions.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="pt-2">
              <button type="button" @click="nextStep"
                class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center">
                Get Started
                <Icon name="fa7-solid:arrow-right" class="ml-2" />
              </button>
            </div>
          </div>

          <!-- Step 2: Scan QR Code -->
          <div v-show="currentStep === 2" class="step-container">
            <div class="mb-8">
              <p class="text-gray-600 text-center mb-6">
                Open your authenticator app and scan this QR code to enroll your device.
              </p>

              <div class="flex justify-center mb-6">
                <canvas ref="qrcodeCanvas"></canvas>
              </div>

              <div class="mb-6">
                <h4 class="font-medium text-gray-800 mb-2 text-center">Can't scan the code?</h4>
                <p class="text-gray-600 text-sm mb-4 text-center">
                  Enter this secret key manually into your authenticator app:
                </p>
                <div class="flex items-center justify-center mb-4">
                  <div class="secret-key">{{ secretKey }}</div>
                  <button @click="copySecret" class="copy-btn p-2 rounded-lg transition-colors"
                    :class="copied ? 'text-green-500' : 'text-gray-500 hover:text-gray-700'">
                    <Icon :name="copied ? 'fa7-solid:circle-check' : 'fa-regular:copy'" />
                  </button>
                </div>
              </div>
            </div>

            <div class="flex justify-between pt-2">
              <button type="button" @click="prevStep"
                class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-medium py-3 px-6 rounded-lg transition duration-200 flex items-center justify-center">
                <Icon name="fa7-solid:arrow-left" class="mr-2" />
                Back
              </button>
              <button type="button" @click="nextStep"
                class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-6 rounded-lg transition duration-200 flex items-center justify-center">
                Next
                <Icon name="fa7-solid:arrow-right" class="ml-2" />
              </button>
            </div>
          </div>

          <!-- Step 3: Verification -->
          <div v-show="currentStep === 3" class="step-container">
            <div class="mb-8">
              <p class="text-gray-600 text-center mb-6">
                Enter the 6-digit verification code from your authenticator app to confirm setup.
              </p>

              <form @submit.prevent="handleVerify" class="space-y-4">
                <div>
                  <label for="verificationCode"
                    class="block text-sm font-medium text-gray-700 mb-2 text-center">Verification
                    Code</label>
                  <div class="flex justify-center">
                    <input v-model="verificationCode" type="text" id="verificationCode" maxlength="6" required
                      class="verification-code-input form-input w-48 text-center py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition duration-200"
                      placeholder="000000" autocomplete="one-time-code" @input="errorMsg = ''">
                  </div>
                  <p v-if="errorMsg" class="mt-2 text-sm text-red-600 text-center">
                    {{ errorMsg }}
                  </p>
                </div>

                <div class="bg-blue-50 p-4 rounded-lg mt-6">
                  <div class="flex">
                    <div class="flex-shrink-0">
                      <Icon name="fa7-solid:lightbulb" class="text-blue-500 mt-0.5" />
                    </div>
                    <div class="ml-3">
                      <h3 class="text-sm font-medium text-blue-800">Don't see a code?</h3>
                      <div class="mt-1 text-sm text-blue-700">
                        <p>Make sure the time on your authenticator app is synchronized correctly. The code refreshes
                          every 30 seconds.</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="flex justify-between pt-6">
                  <button type="button" @click="prevStep"
                    class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-medium py-3 px-6 rounded-lg transition duration-200 flex items-center justify-center">
                    <Icon name="fa7-solid:arrow-left" class="mr-2" />
                    Back
                  </button>
                  <button type="submit" :disabled="isVerifying"
                    class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-6 rounded-lg transition duration-200 flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed">
                    <Icon v-if="isVerifying" name="fa7-solid:circle-notch" class="animate-spin mr-2" />
                    <Icon v-else name="fa7-solid:check" class="mr-2" />
                    Verify & Enable
                  </button>
                </div>
              </form>
            </div>
          </div>

          <!-- Step 4: Success -->
          <div v-show="currentStep === 4" class="step-container text-center">
            <div class="mb-8">
              <div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Icon name="fa7-solid:check" class="text-green-600 text-2xl" />
              </div>
              <h3 class="text-xl font-semibold text-gray-800 mb-2">Setup Complete!</h3>
              <p class="text-gray-600">
                Your authenticator app has been successfully enrolled. You can now use it to verify sign-ins and secure
                your account.
              </p>
            </div>

            <div class="bg-green-50 p-4 rounded-lg mb-6 text-left">
              <div class="flex">
                <div class="flex-shrink-0">
                  <Icon name="fa7-solid:shield-halved" class="text-green-500 mt-1" />
                </div>
                <div class="ml-3">
                  <h3 class="text-sm font-medium text-green-800">What's Next?</h3>
                  <div class="mt-2 text-sm text-green-700">
                    <p>Authenticator app authentication is now enabled for your account.</p>
                  </div>
                </div>
              </div>
            </div>

            <div class="pt-2">
              <NuxtLink to="/two-factor"
                class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center">
                Go back to Two-Factor Settings
                <Icon name="fa7-solid:arrow-right" class="ml-2" />
              </NuxtLink>
            </div>
          </div>
        </div>
      </div>

      <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100 mt-6">
        <p class="text-gray-500 text-xs sm:text-sm">
          Need help? <a :href="contactLink" class="text-blue-600 hover:underline font-medium">Contact Support</a>
        </p>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.form-input:focus {
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}

.step-indicator {
  display: flex;
  justify-content: space-between;
  margin-bottom: 40px;
  position: relative;
}

.step-indicator::before {
  content: '';
  position: absolute;
  top: 18px;
  left: 0;
  right: 0;
  height: 2px;
  background-color: #e5e7eb;
  z-index: 0;
}

.step-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  position: relative;
  z-index: 1;
  background-color: white;
  padding: 0 10px;
}

.step-number {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  flex-shrink: 0;
  transition: all 0.3s ease;
}

.step-active .step-number {
  background-color: #3b82f6;
  color: white;
  box-shadow: 0 2px 4px rgba(59, 130, 246, 0.3);
}

.step-completed .step-number {
  background-color: #10b981;
  color: white;
}

.step-inactive .step-number {
  background-color: #f3f4f6;
  color: #9ca3af;
  border: 1px solid #e5e7eb;
}

.step-label {
  font-size: 14px;
  font-weight: 500;
  color: #6b7280;
  margin-top: 8px;
  text-align: center;
}

.step-active .step-label {
  color: #3b82f6;
  font-weight: 600;
}

.step-completed .step-label {
  color: #10b981;
}

.secret-key {
  font-family: monospace;
  background-color: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 8px 12px;
  letter-spacing: 1px;
}

.app-icons {
  display: flex;
  justify-content: center;
  gap: 20px;
  margin-top: 16px;
}

.app-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.verification-code-input {
  letter-spacing: 8px;
  font-size: 24px;
  font-weight: bold;
}
</style>

<script setup lang="ts">
import auth from '~/middlewares/auth'

useHead({
  title: useSiteTitle('Set Up Authenticator App'),
})

definePageMeta({
  layout: 'dashboard',
  middleware: auth
})

const config = useRuntimeConfig().public
const contactLink = config.contactLink as string || '#'

const api = useApi()
const secretKey = ref('')
const enrollmentUrl = ref('')

const fetchEnrollment = async () => {
  try {
    const data = await api.getTOTPEnrollment()
    secretKey.value = data.secret
    enrollmentUrl.value = data.enrollmentUrl
  } catch (error: any) {
    throw createError({
      statusCode: error.code || 500,
      message: error.message
    })
  }
}

const currentStep = ref(1)
const stepLabels = ['Setup App', 'Scan Code', 'Verify', 'Finish']

const verificationCode = ref('')
const errorMsg = ref('')
const isVerifying = ref(false)
const copied = ref(false)

const qrcodeCanvas = ref<HTMLCanvasElement | null>(null)

const showStep = (step: number) => {
  currentStep.value = step
  window.history.replaceState(null, '', `#step${step}`)
}

const nextStep = () => {
  if (currentStep.value < 4) {
    showStep(currentStep.value + 1)
  }
}

const prevStep = () => {
  if (currentStep.value > 1) {
    showStep(currentStep.value - 1)
  }
}

const copySecret = () => {
  if (!secretKey.value) return
  navigator.clipboard.writeText(secretKey.value).then(() => {
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 2000)
  })
}

const handleVerify = async () => {
  const code = verificationCode.value.trim()
  if (code.length !== 6 || !/^\d+$/.test(code)) {
    errorMsg.value = 'Please enter a valid 6-digit verification code.'
    return
  }

  isVerifying.value = true
  errorMsg.value = ''

  try {
    await api.enrollTOTP(code)
    nextStep()
  } catch (error: any) {
    errorMsg.value = error.message || 'Verification failed. Please check the code and try again.'
  } finally {
    isVerifying.value = false
  }
}

const initializeQR = () => {
  if (currentStep.value === 2 && qrcodeCanvas.value && enrollmentUrl.value) {
    const QRCode = (window as any).QRCode
    if (QRCode?.toCanvas) {
      QRCode.toCanvas(qrcodeCanvas.value, enrollmentUrl.value, {
        width: 250,
        margin: 2,
        color: {
          dark: '#1f2937',
          light: '#ffffff'
        }
      })
    } else {
      // Retry if QRCode not loaded yet
      setTimeout(initializeQR, 100)
    }
  }
}

watch(currentStep, (newStep) => {
  if (newStep === 2) {
    nextTick(initializeQR)
  }
})

onMounted(async () => {
  await fetchEnrollment()

  const hash = window.location.hash
  if (hash.startsWith('#step')) {
    const step = parseInt(hash.replace('#step', ''))
    if (!isNaN(step) && step >= 1 && step <= 4) {
      currentStep.value = step
    }
  }

  if (currentStep.value === 2) {
    initializeQR()
  }
})
</script>
