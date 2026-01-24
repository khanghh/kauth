<template>
  <div class="max-w-4xl mx-auto">
    <div class="mb-8">
      <div class="flex items-center mb-2">
        <NuxtLink
          to="/"
          aria-label="Back"
          class="md:hidden flex items-center mr-2">
          <Icon name="fa7-solid:arrow-left" class="text-gray-700 w-8 h-8" />
        </NuxtLink>
        <h1 class="text-2xl font-bold text-gray-800 leading-none">
          Two-Factor Authentication
        </h1>
      </div>
      <p class="text-gray-600">
        Add an extra layer of security to your account
      </p>
    </div>

    <div v-if="effectiveSuccessMsg" class="alert-box success">
      <div class="flex items-center">
        <Icon name="fa-solid:check-circle" class="mr-2" />
        <span>{{ effectiveSuccessMsg }}</span>
      </div>
    </div>

    <div v-if="effectiveWarningMsg" class="alert-box warning">
      <div class="flex items-center">
        <Icon name="fa-solid:exclamation-triangle" class="mr-2" />
        <span>{{ effectiveWarningMsg }}</span>
      </div>
    </div>

    <div v-if="effectiveErrorMsg" class="alert-box error">
      <div class="flex items-center">
        <Icon name="fa-solid:exclamation-circle" class="mr-2" />
        <span>{{ effectiveErrorMsg }}</span>
      </div>
    </div>

    <form ref="formEl" method="POST">
      <input type="hidden" name="_csrf" :value="csrfToken" />

      <div class="space-y-6">
        <div class="method-card p-6 bg-white" :class="{ active: emailEnabled }">
          <div class="flex items-start justify-between">
            <div class="flex items-start space-x-4">
              <div class="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center">
                <Icon name="fa-solid:envelope" class="text-blue-600 text-xl" />
              </div>
              <div>
                <h3 class="font-bold text-gray-800 text-lg mb-1">Email Authentication</h3>
                <div class="flex items-center text-sm text-gray-500">
                  <Icon name="fa-solid:envelope" class="mr-2" />
                  <span>{{ email || 'No email address configured' }}</span>
                </div>
                <div v-if="emailEnabled" class="mt-2 text-sm text-green-600">
                  <Icon name="fa-solid:check-circle" class="mr-1" />
                  <span>Email authentication is enabled</span>
                </div>
              </div>
            </div>

            <div class="flex items-center space-x-4">
              <label class="toggle-switch">
                <input
                  type="checkbox"
                  name="emailEnabled"
                  value="true"
                  v-model="emailEnabled"
                  @change="submitForm" />
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>
        </div>

        <div class="method-card p-6 bg-white" :class="{ active: smsEnabled }">
          <div class="flex items-start justify-between">
            <div class="flex items-start space-x-4">
              <div class="w-12 h-12 rounded-full bg-green-100 flex items-center justify-center">
                <Icon name="fa-solid:mobile" class="text-green-600 text-xl" />
              </div>
              <div>
                <h3 class="font-bold text-gray-800 text-lg mb-1">SMS Authentication</h3>
                <div class="flex items-center text-sm text-gray-500">
                  <Icon name="fa-solid:phone" class="mr-2" />
                  <span>{{ phoneNumber || 'No phone number added' }}</span>
                </div>
                <div v-if="smsEnabled" class="mt-2 text-sm text-green-600">
                  <Icon name="fa-solid:check-circle" class="mr-1" />
                  <span>SMS authentication is enabled</span>
                </div>
              </div>
            </div>

            <div class="flex items-center space-x-4">
              <label class="toggle-switch">
                <input type="checkbox" v-model="smsEnabled" :disabled="!phoneNumber" @change="onSMSToggle" />
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div v-if="!phoneNumber" class="mt-4 pt-4 border-t border-gray-100">
            <p class="text-sm text-gray-600 mb-3">Add a phone number to enable SMS authentication:</p>
            <div class="flex space-x-3">
              <input
                type="tel"
                v-model="phoneInput"
                class="flex-1 px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="+1 (555) 123-4567" />
              <button type="button" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
                @click="addPhone">
                Add Phone
              </button>
            </div>
          </div>
        </div>

        <div class="method-card p-6 bg-white" :class="{ active: totpEnabled }">
          <div class="flex items-start justify-between">
            <div class="flex items-start space-x-4">
              <div class="w-12 h-12 rounded-full bg-purple-100 flex items-center justify-center">
                <Icon name="fa7-solid:mobile-screen-button" class="text-purple-600 text-xl" />
              </div>
              <div>
                <h3 class="font-bold text-gray-800 text-lg mb-1">Authenticator App</h3>
                <div class="text-sm text-gray-500">
                  <Icon name="fa-solid:clock" class="mr-2" />
                  <span>Time-based verification codes</span>
                </div>
                <div v-if="totpEnabled" class="mt-2 text-sm text-green-600">
                  <Icon name="fa-solid:check-circle" class="mr-1" />
                  <span>Authenticator app is configured</span>
                </div>
              </div>
            </div>

            <div class="flex items-center space-x-4">
              <div v-if="totpEnabled">
                <label class="toggle-switch">
                  <input
                    type="checkbox"
                    name="totpEnabled"
                    value="true"
                    v-model="totpEnabled"
                    @change="onTOTPToggle" />
                  <span class="toggle-slider"></span>
                </label>
              </div>
              <div v-else>
                <NuxtLink to="/totp-enrollment"
                  class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                  Set Up
                </NuxtLink>
              </div>
            </div>
          </div>
        </div>
      </div>
    </form>

    <div v-if="totpEnabled" class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 mt-8">
      <div class="flex items-center justify-between mb-4">
        <div>
          <h2 class="text-lg font-bold text-gray-800">Backup Codes</h2>
          <p class="text-gray-600 text-sm">Use these codes if you lose access to your authenticator app</p>
        </div>
        <div class="text-sm text-gray-500">{{ backupCodes.length }} codes remaining</div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <div v-for="code in backupCodes" :key="code" class="backup-code">{{ code }}</div>
      </div>

      <div class="flex flex-wrap gap-3">
        <button type="button" class="copy-btn" @click="copyAllCodes">
          <Icon name="fa-solid:copy" class="mr-1" /> Copy All
        </button>
        <button type="button" class="copy-btn" @click="downloadCodes">
          <Icon name="fa-solid:download" class="mr-1" /> Download
        </button>
        <button type="button" class="px-4 py-2 bg-red-50 text-red-600 rounded-lg hover:bg-red-100"
          @click="regenerateCodes">
          <Icon name="fa-solid:rotate" class="mr-1" /> Regenerate Codes
        </button>
      </div>

      <div class="mt-4 text-sm text-gray-500">
        <Icon name="fa-solid:info-circle" class="mr-1" />
        Each code can only be used once. Store them in a secure place.
      </div>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-xl p-6 mt-8">
      <div class="flex items-start">
        <Icon name="fa-solid:shield-halved" class="text-blue-500 mt-1 mr-3 text-xl" />
        <div>
          <h3 class="font-medium text-blue-800 text-lg mb-2">Why Enable Two-Factor Authentication?</h3>
          <ul class="text-sm text-blue-700 space-y-2">
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Extra Security:</strong> Even if someone steals your password, they can't access your
                account without the second factor</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Protection Against Phishing:</strong> 2FA codes are unique and time-sensitive, making
                phishing attacks much harder</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Compliance:</strong> Many services and regulations now require or recommend 2FA for enhanced
                security</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa-solid:check" class="mr-2 mt-0.5 text-xs" />
              <span><strong>Peace of Mind:</strong> Know that your account has an additional layer of protection</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'

definePageMeta({
  layout: 'dashboard',
})

useHead({
  title: useSiteTitle('Two-Factor Authentication'),
})

const formEl = ref<HTMLFormElement | null>(null)

const errorMsg = useServerVar<string>('errorMsg', '')
const successMsg = useServerVar<string>('successMsg', '')
const warningMsg = useServerVar<string>('warningMsg', '')
const csrfToken = useServerVar<string>('csrfToken', '')

const emailEnabled = useServerVar<boolean>('emailEnabled', false)
const totpEnabled = useServerVar<boolean>('totpEnabled', false)
const email = useServerVar<string>('email', '')

// Mock SMS state (UI only)
const phoneNumber = useServerVar<string>('phoneNumber', '')
const smsEnabled = useServerVar<boolean>('smsEnabled', false)
const phoneInput = ref('')

const uiSuccessMsg = ref('')
const uiWarningMsg = ref('')
const uiErrorMsg = ref('')

const effectiveSuccessMsg = computed(() => uiSuccessMsg.value || successMsg.value)
const effectiveWarningMsg = computed(() => uiWarningMsg.value || warningMsg.value)
const effectiveErrorMsg = computed(() => uiErrorMsg.value || errorMsg.value)

const clearUiAlerts = () => {
  uiSuccessMsg.value = ''
  uiWarningMsg.value = ''
  uiErrorMsg.value = ''
}

const submitForm = () => {
  clearUiAlerts()
  formEl.value?.submit()
}

const onTOTPToggle = () => {
  clearUiAlerts()

  if (!totpEnabled.value) {
    const ok = confirm(
      'Are you sure you want to disable the authenticator app? You may need to set it up again to re-enable.'
    )
    if (!ok) {
      totpEnabled.value = true
      return
    }
  }
  submitForm()
}

const addPhone = () => {
  clearUiAlerts()
  const value = phoneInput.value.trim()
  if (!value) {
    uiErrorMsg.value = 'Please enter a phone number.'
    return
  }
  if (value.replace(/\D/g, '').length < 10) {
    uiErrorMsg.value = 'Please enter a valid phone number.'
    return
  }
  phoneNumber.value = value
  phoneInput.value = ''
  uiSuccessMsg.value = 'Phone number added successfully. (mock)'
}

const onSMSToggle = () => {
  clearUiAlerts()
  if (!phoneNumber.value) {
    smsEnabled.value = false
    return
  }
  uiSuccessMsg.value = `SMS authentication ${smsEnabled.value ? 'enabled' : 'disabled'}. (mock)`
}

// Backup codes (UI only)
const backupCodes = ref<string[]>([])

const generateBackupCodes = (count = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const codes: string[] = []
  for (let i = 0; i < count; i++) {
    let code = ''
    for (let j = 0; j < 10; j++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    codes.push(code)
  }
  return codes
}

const copyAllCodes = async () => {
  clearUiAlerts()
  try {
    await navigator.clipboard.writeText(backupCodes.value.join('\n'))
    uiSuccessMsg.value = 'Backup codes copied to clipboard!'
  } catch {
    uiWarningMsg.value = 'Failed to copy codes. Please copy them manually.'
  }
}

const downloadCodes = () => {
  clearUiAlerts()
  const text = backupCodes.value.join('\n')
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'kauth-backup-codes.txt'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

const regenerateCodes = () => {
  clearUiAlerts()
  if (!confirm('This will invalidate all current backup codes. Are you sure?')) return
  backupCodes.value = generateBackupCodes()
  uiSuccessMsg.value = 'New backup codes generated successfully!'
}

watch(
  () => totpEnabled.value,
  (enabled) => {
    if (enabled && backupCodes.value.length === 0) {
      backupCodes.value = generateBackupCodes()
    }
  },
  { immediate: true }
)

onMounted(() => {
  if (totpEnabled.value && backupCodes.value.length === 0) {
    backupCodes.value = generateBackupCodes()
  }
})
</script>

<style scoped>
.method-card {
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  transition: all 0.2s ease;
}

.method-card:hover {
  border-color: #d1d5db;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
}

.method-card.active {
  border-color: #4f46e5;
  background-color: #fafaff;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 52px;
  height: 28px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #d1d5db;
  transition: 0.3s;
  border-radius: 34px;
}

.toggle-slider:before {
  position: absolute;
  content: '';
  height: 20px;
  width: 20px;
  left: 4px;
  bottom: 4px;
  background-color: white;
  transition: 0.3s;
  border-radius: 50%;
}

input:checked+.toggle-slider {
  background-color: #4f46e5;
}

input:checked+.toggle-slider:before {
  transform: translateX(24px);
}

.alert-box {
  padding: 12px 16px;
  border-radius: 8px;
  margin-bottom: 20px;
}

.alert-box.success {
  background-color: #d1fae5;
  border: 1px solid #a7f3d0;
  color: #065f46;
}

.alert-box.warning {
  background-color: #fef3c7;
  border: 1px solid #fde68a;
  color: #92400e;
}

.alert-box.error {
  background-color: #fee2e2;
  border: 1px solid #fecaca;
  color: #991b1b;
}

.backup-code {
  font-family: 'Courier New', monospace;
  background-color: #f3f4f6;
  padding: 8px 12px;
  border-radius: 6px;
  letter-spacing: 1px;
  font-weight: 600;
  text-align: center;
  border: 1px solid #e5e7eb;
}

.copy-btn {
  background-color: #f3f4f6;
  border: 1px solid #d1d5db;
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.2s;
}

.copy-btn:hover {
  background-color: #e5e7eb;
}
</style>
