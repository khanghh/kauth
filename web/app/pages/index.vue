<template>
  <div class="max-w-4xl mx-auto">
    <div class="text-center mb-12">
      <div class="relative w-32 h-32 mx-auto mb-6">
        <div
          class="w-full h-full rounded-full border-4 border-blue-100 overflow-hidden flex items-center justify-center bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg">
          <img
            v-if="avatarMainOk"
            :src="currentUser.picture"
            alt="Profile"
            class="w-full h-full object-cover"
            @error="avatarMainOk = false">
          <span v-else class="text-white text-5xl font-bold select-none">{{ userInitial }}</span>
        </div>
      </div>

      <h1 class="text-3xl font-bold text-gray-800 mb-2">{{ currentUser.fullName }}</h1>

      <p class="text-gray-600 text-lg inline-flex items-center justify-center">
        <Icon name="fa7-solid:envelope" class="mr-2" />
        {{ currentUser.email }}
      </p>
    </div>

    <MobileNavMenu />
    <RecentActivitySection />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import auth from '~/middlewares/auth'

definePageMeta({
  layout: 'dashboard',
  middleware: auth,
})

const userStore = useUserStore()

const currentUser = computed<UserInfo>(() => {
  if (!userStore.user) {
    return {
      id: '',
      username: '',
      fullName: '',
      email: '',
      picture: ''
    }
  }
  return userStore.user
})

const userInitial = computed(() => (currentUser.value?.username?.trim()?.[0] ?? 'U').toUpperCase())

const avatarMainOk = ref(true)

</script>
