<template>
  <ClientOnly>
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
            Personal Information
          </h1>
        </div>
        <p class="text-gray-600">
          Manage your account details and personal information
        </p>
      </div>

      <div v-if="successMsg"
        class="mb-6 rounded-xl border px-4 py-3 border-green-200 bg-green-50 text-green-800">
        <div class="flex items-center">
          <Icon name="fa7-solid:circle-check" class="mr-2 w-5 h-5" />
          <span>{{ successMsg }}</span>
        </div>
      </div>
      <div v-else-if="errorMsg" class="mb-6 rounded-xl border px-4 py-3 border-red-200 bg-red-50 text-red-800">
        <div class="flex items-center">
          <Icon name="fa7-solid:exclamation-circle" class="mr-2 w-5 h-5" />
          <span>{{ errorMsg }}</span>
        </div>
      </div>

      <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center justify-between mb-6">
          <h2 class="text-lg font-semibold text-gray-800">Profile Picture</h2>
        </div>

        <div class="flex items-center space-x-6">
          <div class="relative">
            <div
              class="w-24 h-24 rounded-full border-4 border-gray-100 overflow-hidden bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
              <img
                v-if="avatarOk && avatarSrc"
                :src="avatarSrc"
                alt="Profile"
                class="w-full h-full object-cover"
                @error="avatarOk = false" />
              <span v-else class="text-white text-2xl font-bold select-none">{{ userInitial }}</span>
            </div>

            <button
              type="button"
              class="absolute bottom-0 right-0 w-8 h-8 bg-indigo-600 rounded-full flex items-center justify-center border-2 border-white transition hover:bg-indigo-700 hover:scale-105"
              @click="triggerAvatarPicker">
              <Icon name="fa7-solid:pencil" class="text-white w-4 h-4" />
            </button>

            <input ref="fileInputEl" type="file" accept="image/*" class="hidden" @change="onAvatarFileChange" />
          </div>

          <div class="flex-1">
            <div class="mb-4">
              <h3 class="font-medium text-gray-800 mb-2">Upload a new photo</h3>
              <p class="text-gray-600 text-sm">
                JPG, GIF or PNG. Max size of 2MB. Recommended: 400x400px for best quality.
              </p>
            </div>
            <div class="flex items-center space-x-3">
              <button type="button"
                class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
                @click="triggerAvatarPicker">
                Change
              </button>
              <button type="button"
                class="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium">
                Remove photo
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-6">Personal Details</h2>

        <form class="space-y-6" @submit="onSubmit">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Full Name</label>
            <div class="relative">
              <Icon name="fa7-solid:user" class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                name="fullName"
                type="text"
                v-model="form.fullName"
                class="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-xl input-focus transition"
                placeholder="Enter your full name" />
            </div>
            <p class="mt-2 text-sm text-gray-500">This is how your name will appear across all services</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <div class="relative">
              <Icon name="fa7-solid:user-tag" class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                name="username"
                type="text"
                v-model="form.username"
                readonly
                disabled
                class="w-full pl-12 pr-4 py-3 border border-gray-300 bg-gray-50 rounded-xl text-gray-600"
                placeholder="username" />
            </div>
            <p class="mt-2 text-sm text-gray-500">Used for login and mentions</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <div class="relative">
              <Icon name="fa7-solid:envelope" class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                name="email"
                type="email"
                :value="email"
                readonly
                class="w-full pl-12 pr-4 py-3 border border-gray-300 bg-gray-50 rounded-xl text-gray-600" />
              <NuxtLink to="/"
                class="absolute right-3 top-1/2 -translate-y-1/2 text-indigo-600 hover:text-indigo-800 text-sm font-medium">
                Change
              </NuxtLink>
            </div>
            <p class="mt-2 text-sm text-gray-500">Your primary email for account notifications</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Birthday</label>
            <div class="relative">
              <Icon name="fa7-solid:cake-candles"
                class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                name="birthday"
                type="date"
                v-model="birthdayString"
                :max="todayISO"
                :min="minBirthdayISO"
                class="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-xl input-focus transition text-gray-700 appearance-none -webkit-appearance-none" />
            </div>
            <p class="mt-2 text-sm text-gray-500">Your date of birth</p>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
            <div class="relative">
              <Icon name="fa7-solid:phone" class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                name="phone"
                type="tel"
                v-model="form.phone"
                class="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-xl input-focus transition"
                placeholder="+1 (555) 000-0000" />
            </div>
            <p class="mt-2 text-sm text-gray-500">Used for account verification and important security alerts. We will
              only call or text you with your permission.</p>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">Country</label>
            <div class="relative">
              <Icon name="fa7-solid:earth-americas"
                class="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
              <select
                name="location"
                v-model="form.location"
                class="w-full pl-12 pr-10 py-3 border border-gray-300 rounded-xl input-focus transition text-gray-700 appearance-none -webkit-appearance-none">
                <option value="">Select your country</option>
                <option v-for="country in countries" :key="country.code" :value="country.code">
                  {{ country.name }}
                </option>
              </select>
              <div class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none">
                <Icon name="fa7-solid:angle-down" class="w-4 h-4" />
              </div>
            </div>
            <p class="mt-2 text-sm text-gray-500">Used to personalize content and localize features.</p>
          </div>

          <div class="flex items-center justify-between pt-6 border-t border-gray-200">
            <div class="text-sm text-gray-500">{{ lastUpdatedText }}</div>
            <div class="flex space-x-3">
              <button
                type="submit"
                :disabled="isSubmitting"
                class="flex items-center px-6 py-3 text-white rounded-xl font-medium bg-indigo-600 hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed">
                <Icon v-if="isSubmitting" name="fa7-solid:spinner" class="animate-spin mr-2 w-5 h-5" />
                <Icon v-else name="fa7-solid:save" class="mr-2 w-5 h-5" />
                {{ isSubmitting ? 'Saving...' : 'Save Changes' }}
              </button>
            </div>
          </div>
        </form>
      </div>

      <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
        <div>
          <div class="flex items-center mb-1">
            <Icon name="fa7-solid:shield-halved" class="text-blue-500 mr-2" />
            <h3 class="font-medium text-blue-800">Your Privacy Matters</h3>
          </div>
          <div>
            <p class="text-sm text-blue-700">
              We only use your personal information to provide and improve our services.
              Your birthday is used for age verification and personalized experiences.
              We never share your personal data with third parties without your consent.
            </p>
          </div>
        </div>
      </div>

      <!-- Cropper Modal -->
      <AvatarCropDialog
        :show="isCropperOpen"
        :image="cropperImage"
        @close="closeCropper"
        @save="onCropSaved" />
    </div>
  </ClientOnly>
</template>

<style scoped>
.input-focus:focus {
  outline: none;
  border-color: #4f46e5;
  box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.18);
}
</style>

<script setup lang="ts">
import type { PersonalInfo, PersonalInfoUpdate } from '~/composables/useApi'
import { countries } from '~/composables/validate'
import auth from '~/middlewares/auth'

const api = useApi()

definePageMeta({
  layout: 'dashboard',
  middleware: auth
})

useHead({ title: useSiteTitle('Personal Information') })

const personalInfo = ref<PersonalInfo>({} as PersonalInfo)

onMounted(async () => {
  try {
    const data = await api.getPersonalInfo()
    personalInfo.value = data
    hydrateFormFromProfile(data)
  } catch (err: any) {
    if (err?.code === 401 || err?.statusCode === 401) return
    showError(err?.message ?? 'Failed to fetch profile')
  }
})

const email = computed(() => personalInfo.value?.email ?? '')
const userInitial = computed(() => (personalInfo.value?.username?.[0] ?? 'U').toUpperCase())

// Local editable form (hydrate from `profile` after the client fetch completes)
const form = reactive({ fullName: '', username: '', phone: '', location: '', birthday: 0 })
const original = ref({ ...form })

const birthdayString = computed({
  get: () => {
    if (!form.birthday) return ''
    return new Date(form.birthday * 1000).toISOString().slice(0, 10)
  },
  set: (value: string) => {
    form.birthday = value ? Math.floor(Date.parse(value) / 1000) : 0
  }
})

const hydrateFormFromProfile = (p: PersonalInfo | null | undefined) => {
  if (!p) return

  form.fullName = p.fullName ?? ''
  form.username = p.username ?? ''
  form.phone = p.phoneNumber ?? ''
  form.location = p.country ?? ''
  form.birthday = p.birthday ?? 0

  original.value = { ...form }
}

const successMsg = ref('')
const errorMsg = ref('')
const showSuccess = (msg: string) => { errorMsg.value = ''; successMsg.value = msg }
const showError = (msg: string) => { successMsg.value = ''; errorMsg.value = msg }

const fileInputEl = ref<HTMLInputElement | null>(null)
const avatarOk = ref(true)
const avatarPreviewUrl = ref<string | null>(null)

// Cropper State
const isCropperOpen = ref(false)
const cropperImage = ref('')

const avatarSrc = computed(() => avatarPreviewUrl.value || personalInfo.value?.picture || '')

const revokePreviewUrl = () => {
  if (avatarPreviewUrl.value && avatarPreviewUrl.value.startsWith('blob:')) {
    URL.revokeObjectURL(avatarPreviewUrl.value)
  }
  avatarPreviewUrl.value = null
}

const triggerAvatarPicker = () => fileInputEl.value?.click()

const closeCropper = () => {
  isCropperOpen.value = false
  cropperImage.value = ''
  if (fileInputEl.value) fileInputEl.value.value = ''
}

const onAvatarFileChange = (e: Event) => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (file.size > 2 * 1024 * 1024) return showError('File must be under 2MB')

  const reader = new FileReader()
  reader.onload = (e) => {
    if (e.target?.result) {
      cropperImage.value = e.target.result as string
      isCropperOpen.value = true
    }
  }
  reader.readAsDataURL(file)
}

const onCropSaved = (newImage: string) => {
  revokePreviewUrl()
  avatarOk.value = true
  avatarPreviewUrl.value = newImage
  showSuccess('Profile picture updated successfully!')
  closeCropper()
}

const todayISO = computed(() => {
  const today = new Date()
  return `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`
})

const minBirthdayISO = computed(() => {
  const d = new Date()
  d.setFullYear(d.getFullYear() - 100)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
})

const lastUpdatedText = ref('')
const isSubmitting = ref(false)

const onSubmit = async (e: Event) => {
  e.preventDefault()

  const changes: PersonalInfoUpdate = {}

  if (form.fullName !== original.value.fullName) {
    changes.fullName = form.fullName
  }

  if (form.birthday !== original.value.birthday) {
    changes.birthday = form.birthday
  }

  if (form.phone !== original.value.phone) {
    changes.phoneNumber = form.phone
  }

  if (form.location !== original.value.location) {
    changes.country = form.location
  }

  if (Object.keys(changes).length > 0) {
    isSubmitting.value = true
    await api.updatePersonalInfo(changes).then(() => {
      original.value = { ...form }
      const now = new Date()
      lastUpdatedText.value = `Last updated: ${now.toLocaleString()}`
      showSuccess('Profile updated successfully! (mock)')
      isSubmitting.value = false
    }).catch(err => {
      const errMsg = err.message || 'Internal server error'
      showError(errMsg)
      isSubmitting.value = false
    })
  }
}

onBeforeUnmount(revokePreviewUrl)
</script>
