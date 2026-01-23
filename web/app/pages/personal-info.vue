<template>
  <ClientOnly>

    <div class="max-w-4xl mx-auto">
      <!-- Header -->
      <div class="mb-8">
        <h1 class="text-2xl font-bold text-gray-800 mb-2">Personal Information</h1>
        <p class="text-gray-600">Manage your account details and personal information</p>
      </div>

      <div v-if="successMsg"
        class="mb-6 rounded-xl border px-4 py-3 border-green-200 bg-green-50 text-green-800">
        <div class="flex items-center">
          <Icon name="fa-solid:check-circle" class="mr-2" />
          <span>{{ successMsg }}</span>
        </div>
      </div>
      <div v-else-if="errorMsg" class="mb-6 rounded-xl border px-4 py-3 border-red-200 bg-red-50 text-red-800">
        <div class="flex items-center">
          <Icon name="fa-solid:exclamation-circle" class="mr-2" />
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
              <Icon name="fa7-solid:pencil" class="text-white text-xs" />
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
            <label for="fullName" class="block text-sm font-medium text-gray-700 mb-2">Full Name</label>
            <input
              id="fullName"
              name="fullName"
              type="text"
              v-model="form.fullName"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="Enter your full name" />
            <p class="mt-2 text-sm text-gray-500">This is how your name will appear across all services</p>
          </div>

          <div>
            <label for="username" class="block text-sm font-medium text-gray-700 mb-2">Username</label>
            <div class="relative">
              <span class="absolute left-4 top-3 text-gray-500">@</span>
              <input
                id="username"
                name="username"
                type="text"
                v-model="form.username"
                class="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl input-focus transition"
                placeholder="username" />
            </div>
            <p class="mt-2 text-sm text-gray-500">Used for login and mentions</p>
          </div>

          <div>
            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
            <div class="relative">
              <input
                id="email"
                name="email"
                type="email"
                :value="email"
                readonly
                class="w-full px-4 py-3 pr-24 border border-gray-300 bg-gray-50 rounded-xl text-gray-600" />
              <NuxtLink to="/"
                class="absolute right-3 top-1/2 -translate-y-1/2 text-indigo-600 hover:text-indigo-800 text-sm font-medium">
                Change
              </NuxtLink>
            </div>
            <p class="mt-2 text-sm text-gray-500">Your primary email for account notifications</p>
          </div>

          <div>
            <label for="birthday" class="block text-sm font-medium text-gray-700 mb-2">Birthday</label>
            <input
              id="birthday"
              name="birthday"
              type="date"
              v-model="form.birthday"
              :max="todayISO"
              :min="minBirthdayISO"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition text-gray-700" />
            <p class="mt-2 text-sm text-gray-500">Your date of birth</p>
          </div>
          <div>
            <label for="phone" class="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
            <input
              id="phone"
              name="phone"
              type="tel"
              v-model="form.phone"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="+1 (555) 000-0000" />
            <p class="mt-2 text-sm text-gray-500">Used for account verification and important security alerts. We will
              only call or text you with your permission.</p>
          </div>
          <div>
            <label for="location" class="block text-sm font-medium text-gray-700 mb-2">Location</label>
            <input
              id="location"
              name="location"
              type="text"
              v-model="form.location"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="Your location" />
            <p class="mt-2 text-sm text-gray-500">City, state, or country — used to personalize content and localize
              features.</p>
          </div>

          <div class="flex items-center justify-between pt-6 border-t border-gray-200">
            <div class="text-sm text-gray-500">{{ lastUpdatedText }}</div>
            <div class="flex space-x-3">
              <button
                type="submit"
                class="px-6 py-3 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed">
                Save Changes
              </button>
            </div>
          </div>
        </form>
      </div>

      <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
        <div class="flex items-start">
          <Icon name="fa7-solid:shield-halved" class="text-blue-500 mr-3 text-2xl" />
          <div>
            <h3 class="font-medium text-blue-800 mb-1">Your Privacy Matters</h3>
            <p class="text-sm text-blue-700">
              We only use your personal information to provide and improve our services.
              Your birthday is used for age verification and personalized experiences.
              We never share your personal data with third parties without your consent.
            </p>
          </div>
        </div>
      </div>

      <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 mt-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-6">Connected Accounts</h2>
        <div class="space-y-4">
          <div class="service-card flex items-center justify-between p-4 border border-gray-200 rounded-xl">
            <div class="flex items-center">
              <div class="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mr-4">
                <Icon name="fa-brands:google" class="text-blue-600" />
              </div>
              <div>
                <div class="flex items-center gap-2">
                  <div class="font-medium text-gray-800">Google</div>
                  <span
                    class="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full inline-flex items-center">Connected</span>
                </div>
                <div class="text-sm text-gray-500">{{ email }}</div>
              </div>
            </div>
            <div class="flex items-center space-x-2">
              <button type="button" class="text-red-600 hover:text-red-800 text-sm font-medium"
                @click="disconnectGoogle">
                Disconnect
              </button>
            </div>
          </div>

          <div class="service-card flex items-center justify-between p-4 border border-gray-200 rounded-xl">
            <div class="flex items-center">
              <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
                <Icon name="fa-brands:github" class="text-gray-800" />
              </div>
              <div>
                <div class="font-medium text-gray-800">GitHub</div>
                <div class="text-sm text-gray-500">Not connected</div>
              </div>
            </div>
            <button
              type="button"
              class="px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900 text-sm font-medium transition"
              @click="connectGithub">
              Connect
            </button>
          </div>
        </div>
      </div>

      <MobileNavMenu />

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
import { computed, reactive, ref, onMounted, onBeforeUnmount } from 'vue'
import type { UserProfile } from '~/composables/useApi'

const api = useApi()

definePageMeta({
  layout: 'dashboard',
})

useHead({ title: useSiteTitle('Personal Information') })

const profile = ref<UserProfile>({} as UserProfile)

onMounted(async () => {
  try {
    const data = await api.getUserProfile()
    profile.value = data
    hydrateFormFromProfile(data)
  } catch (err: any) {
    if (err?.code === 401 || err?.statusCode === 401) return
    showError(err?.message ?? 'Failed to fetch profile')
  }
})

const email = computed(() => profile.value?.email ?? '')
const userInitial = computed(() => (profile.value?.username?.[0] ?? 'U').toUpperCase())

// Local editable form (hydrate from `profile` after the client fetch completes)
const form = reactive({ fullName: '', username: '', phone: '', location: '', birthday: '' })
const original = ref({ ...form })

const hydrateFormFromProfile = (p: UserProfile | null | undefined) => {
  if (!p) return

  form.fullName = p.fullName ?? ''
  form.username = p.username ?? ''
  form.phone = p.phoneNumber ?? ''
  form.location = p.country ?? ''

  if (p.birthDate) {
    const ms = p.birthDate < 100000000000 ? p.birthDate * 1000 : p.birthDate
    try {
      form.birthday = new Date(ms).toISOString().split('T')[0]
    } catch { form.birthday = '' }
  } else {
    form.birthday = ''
  }

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

const avatarSrc = computed(() => avatarPreviewUrl.value || profile.value?.picture || '')

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
  revokePreviewUrl()
  avatarOk.value = false
  showSuccess('Profile picture removed (preview)')
}

const todayISO = computed(() => new Date().toISOString().split('T')[0])
const minBirthdayISO = computed(() => {
  const d = new Date(); d.setFullYear(d.getFullYear() - 100)
  return d.toISOString().split('T')[0]
})

const lastUpdatedText = ref('')

const onSubmit = () => {
  original.value = { ...form }

  const now = new Date()
  lastUpdatedText.value = `Last updated: ${now.toLocaleString()}`
  showSuccess('Profile updated successfully! (mock)')
}

const disconnectGoogle = () => {
  if (!confirm('Are you sure you want to disconnect your Google account? This may affect your ability to sign in.')) return
  showSuccess('Google account disconnected. (mock)')
}

const connectGithub = () => {
  showSuccess('Redirecting to GitHub authorization... (mock)')
}

onBeforeUnmount(revokePreviewUrl)

onMounted(async () => {
  try {
    const data = await api.getUserProfile()
    profile.value = data
    console.log('data: ', data)
  } catch (err: any) {
    if (err?.code === 401 || err?.statusCode === 401) {
      throw createError({
        statusCode: 401
      })
    }
    showError(err?.message ?? 'Failed to fetch profile')
  }
})

</script>
