<template>
  <div class="max-w-4xl mx-auto">
    <div class="mb-8">
      <h1 class="text-2xl font-bold text-gray-800 mb-2">Personal Information</h1>
      <p class="text-gray-600">Manage your account details and personal information</p>
    </div>

    <div v-if="noticeMsg" class="mb-6 rounded-xl border px-4 py-3" :class="noticeClass">
      <div class="flex items-center">
        <Icon :name="noticeIcon" class="mr-2" />
        <span>{{ noticeMsg }}</span>
      </div>
    </div>

    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 mb-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-lg font-semibold text-gray-800">Profile Picture</h2>
        <button
          type="button"
          class="text-sm text-indigo-600 hover:text-indigo-800 font-medium"
          @click="triggerAvatarPicker">
          Change
        </button>
      </div>

      <div class="flex items-center space-x-6">
        <div class="relative">
          <div
            class="w-24 h-24 rounded-full border-4 border-gray-100 overflow-hidden bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
            <img
              v-if="avatarOk"
              :src="avatarSrc"
              alt="Profile"
              class="w-full h-full object-cover"
              @error="avatarOk = false" />
            <span v-else class="text-white text-2xl font-bold select-none">{{ userInitial }}</span>
          </div>

          <button type="button" class="profile-edit-icon" @click="triggerAvatarPicker"
            aria-label="Change profile picture">
            <Icon name="fa-solid:pencil" class="text-white text-xs" />
          </button>

          <input
            ref="fileInputEl"
            type="file"
            accept="image/*"
            class="hidden"
            @change="onAvatarFileChange" />
        </div>

        <div class="flex-1">
          <p class="text-gray-600 text-sm mb-2">JPG, GIF or PNG. Max size of 2MB. Recommended: 400x400px</p>
          <button
            type="button"
            class="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium transition"
            @click="removeAvatar">
            Remove photo
          </button>
        </div>
      </div>
    </div>

    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-800 mb-6">Personal Details</h2>

      <form class="space-y-6" @submit="onSubmit">
        <div>
          <label for="displayName" class="block text-sm font-medium text-gray-700 mb-2">Display Name</label>
          <input
            id="displayName"
            name="displayName"
            type="text"
            v-model="displayName"
            class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
            placeholder="Enter your display name" />
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
              v-model="username"
              class="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="username" />
          </div>
          <p class="mt-2 text-sm text-gray-500">Used for login and mentions</p>
        </div>

        <div>
          <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email Address</label>
          <div class="flex items-center space-x-3">
            <input
              id="email"
              name="email"
              type="email"
              :value="email"
              readonly
              class="flex-1 px-4 py-3 border border-gray-300 bg-gray-50 rounded-xl text-gray-600" />
            <div class="flex items-center space-x-2">
              <span class="status-badge verified">
                <Icon name="fa-solid:check" />
                Verified
              </span>
              <NuxtLink to="/" class="text-indigo-600 hover:text-indigo-800 text-sm font-medium">Change</NuxtLink>
            </div>
          </div>
          <p class="mt-2 text-sm text-gray-500">Your primary email for account notifications</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label for="phone" class="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
            <input
              id="phone"
              name="phone"
              type="tel"
              v-model="phone"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="+1 (555) 000-0000" />
          </div>
          <div>
            <label for="location" class="block text-sm font-medium text-gray-700 mb-2">Location</label>
            <input
              id="location"
              name="location"
              type="text"
              v-model="location"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition"
              placeholder="Your location" />
          </div>
          <div>
            <label for="birthday" class="block text-sm font-medium text-gray-700 mb-2">Birthday</label>
            <input
              id="birthday"
              name="birthday"
              type="date"
              v-model="birthday"
              :max="todayISO"
              :min="minBirthdayISO"
              class="w-full px-4 py-3 border border-gray-300 rounded-xl input-focus transition text-gray-700" />
            <p class="mt-2 text-sm text-gray-500">Your date of birth</p>
          </div>
        </div>

        <div class="flex items-center justify-between pt-6 border-t border-gray-200">
          <div class="text-sm text-gray-500">{{ lastUpdatedText }}</div>
          <div class="flex space-x-3">
            <button type="button" class="cancel-btn" @click="onCancel">Cancel</button>
            <button type="submit" class="save-btn">Save Changes</button>
          </div>
        </div>
      </form>
    </div>

    <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 mt-6">
      <div class="flex items-start">
        <Icon name="fa-solid:shield-halved" class="text-blue-500 mt-1 mr-3" />
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
              <div class="font-medium text-gray-800">Google</div>
              <div class="text-sm text-gray-500">{{ email }}</div>
            </div>
          </div>
          <div class="flex items-center space-x-2">
            <span class="status-badge connected">Connected</span>
            <button type="button" class="text-red-600 hover:text-red-800 text-sm font-medium" @click="disconnectGoogle">
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
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'

definePageMeta({
  layout: 'dashboard',
})

useHead({
  title: useSiteTitle('Personal Information'),
})

const username = useServerVar<string>('username', '{{.username}}')
const displayName = useServerVar<string>('displayName', '{{.displayName}}')
const email = useServerVar<string>('email', '{{.email}}')
const avatarUrl = useServerVar<string>('picture', '')

const userInitial = computed(() => (username.value?.trim()?.[0] ?? 'U').toUpperCase())

const fileInputEl = ref<HTMLInputElement | null>(null)
const avatarOk = ref(true)
const avatarPreviewUrl = ref<string | null>(null)

const phone = ref('')
const location = ref('')
const birthday = ref('')

const original = ref({
  displayName: '',
  username: '',
  phone: '',
  location: '',
  birthday: '',
})

const lastUpdatedText = ref('')

const noticeMsg = ref('')
const noticeType = ref<'success' | 'error'>('success')

const noticeClass = computed(() =>
  noticeType.value === 'success'
    ? 'border-green-200 bg-green-50 text-green-800'
    : 'border-red-200 bg-red-50 text-red-800'
)

const noticeIcon = computed(() => (noticeType.value === 'success' ? 'fa-solid:check-circle' : 'fa-solid:exclamation-circle'))

const avatarSrc = computed(() => avatarPreviewUrl.value || avatarUrl.value)

const todayISO = computed(() => new Date().toISOString().split('T')[0])
const minBirthdayISO = computed(() => {
  const d = new Date()
  d.setFullYear(d.getFullYear() - 100)
  return d.toISOString().split('T')[0]
})

const triggerAvatarPicker = () => {
  fileInputEl.value?.click()
}

const revokePreviewUrl = () => {
  if (avatarPreviewUrl.value) {
    URL.revokeObjectURL(avatarPreviewUrl.value)
    avatarPreviewUrl.value = null
  }
}

const onAvatarFileChange = (e: Event) => {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return

  if (file.size > 2 * 1024 * 1024) {
    noticeType.value = 'error'
    noticeMsg.value = 'File size must be less than 2MB.'
    input.value = ''
    return
  }

  revokePreviewUrl()
  avatarOk.value = true
  avatarPreviewUrl.value = URL.createObjectURL(file)
  noticeType.value = 'success'
  noticeMsg.value = 'Profile picture updated (preview only).'
}

const removeAvatar = () => {
  revokePreviewUrl()
  avatarOk.value = false
  noticeType.value = 'success'
  noticeMsg.value = 'Profile picture removed (preview only).'
}

const onCancel = () => {
  if (!confirm('Are you sure you want to discard your changes?')) return

  displayName.value = original.value.displayName
  username.value = original.value.username
  phone.value = original.value.phone
  location.value = original.value.location
  birthday.value = original.value.birthday
  noticeMsg.value = ''
}

const onSubmit = (e: Event) => {
  e.preventDefault()
  noticeMsg.value = ''

  if (birthday.value) {
    const today = new Date()
    const birthDate = new Date(birthday.value)
    if (birthDate > today) {
      noticeType.value = 'error'
      noticeMsg.value = 'Birthday cannot be in the future.'
      return
    }

    const age = today.getFullYear() - birthDate.getFullYear()
    if (age < 13) {
      if (!confirm("You must be at least 13 years old to use this service. Are you sure you entered the correct birthday?")) {
        return
      }
    }
    if (age > 100) {
      if (!confirm('Please confirm your birthday. You appear to be over 100 years old.')) {
        return
      }
    }
  }

  const now = new Date()
  const formattedTime = now.toLocaleString('en-US', {
    weekday: 'long',
    hour: 'numeric',
    minute: '2-digit',
  })
  lastUpdatedText.value = `Last updated: ${formattedTime}`

  original.value = {
    displayName: displayName.value,
    username: username.value,
    phone: phone.value,
    location: location.value,
    birthday: birthday.value,
  }

  noticeType.value = 'success'
  noticeMsg.value = 'Profile updated successfully! (mock)'
}

const disconnectGoogle = () => {
  if (!confirm('Are you sure you want to disconnect your Google account? This may affect your ability to sign in.')) return
  noticeType.value = 'success'
  noticeMsg.value = 'Google account disconnected. (mock)'
}

const connectGithub = () => {
  noticeType.value = 'success'
  noticeMsg.value = 'Redirecting to GitHub authorization... (mock)'
}

const currentPasswordError = ref('')
const confirmPasswordError = ref('')

onBeforeUnmount(() => {
  revokePreviewUrl()
})

// Initialize originals + last updated label
original.value = {
  displayName: displayName.value,
  username: username.value,
  phone: phone.value,
  location: location.value,
  birthday: birthday.value,
}
lastUpdatedText.value = 'Last updated: —'

</script>

<style scoped>
.profile-edit-icon {
  position: absolute;
  bottom: 0;
  right: 0;
  width: 32px;
  height: 32px;
  background-color: #4f46e5;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid white;
  cursor: pointer;
  transition: all 0.2s ease;
}

.profile-edit-icon:hover {
  background-color: #4338ca;
  transform: scale(1.05);
}

.input-focus:focus {
  outline: none;
  border-color: #4f46e5;
  box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.18);
}

.status-badge {
  padding: 4px 12px;
  border-radius: 9999px;
  font-size: 12px;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.status-badge.verified {
  background-color: #dcfce7;
  color: #166534;
}

.status-badge.connected {
  background-color: #dcfce7;
  color: #166534;
}

.service-card {
  transition: all 0.2s ease;
  border-width: 1px;
}

.service-card:hover {
  border-color: #d1d5db;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
}

.save-btn {
  background-color: #4f46e5;
  color: white;
  padding: 12px 24px;
  border-radius: 12px;
  font-weight: 500;
  transition: all 0.2s ease;
}

.save-btn:hover:not(:disabled) {
  background-color: #4338ca;
}

.save-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.cancel-btn {
  padding: 12px 24px;
  border-radius: 12px;
  font-weight: 500;
  border: 1px solid #d1d5db;
  color: #374151;
  transition: all 0.2s ease;
}

.cancel-btn:hover {
  background-color: #f9fafb;
}

input[type='date']::-webkit-calendar-picker-indicator {
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="%236b7280" viewBox="0 0 24 24"><path d="M20 3h-1V1h-2v2H7V1H5v2H4c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 18H4V8h16v13z"/></svg>');
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
}

input[type='date']::-webkit-calendar-picker-indicator:hover {
  background-color: #f3f4f6;
}
</style>
