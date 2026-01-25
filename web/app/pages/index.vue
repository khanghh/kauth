<template>
  <div class="max-w-4xl mx-auto">
    <div class="text-center mb-12">
      <div class="relative w-32 h-32 mx-auto mb-6">
        <div
          class="w-full h-full rounded-full border-4 border-blue-100 overflow-hidden flex items-center justify-center bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg">
          <img
            v-if="avatarMainOk && currentUser.picture"
            :src="currentUser.picture"
            alt="Profile"
            class="w-full h-full object-cover"
            @error="avatarMainOk = false">
          <span v-else class="text-white text-5xl font-bold select-none">{{ userInitial }}</span>
        </div>
      </div>

      <h1 class="text-3xl font-bold text-gray-800 mb-2">{{ currentUser.fullName }}</h1>

      <p class="text-gray-600 text-lg inline-flex items-center justify-center">
        <Icon name="fa7-solid:at" />
        {{ currentUser.username }}
      </p>
    </div>

    <MobileNavMenu />

    <section class="mt-12">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-800">Recent Activity</h2>
      </div>

      <div v-if="pending" class="space-y-4 animate-pulse">
        <div v-for="i in 3" :key="i" class="h-24 bg-gray-100 rounded-xl border border-gray-200" />
      </div>

      <div v-else-if="activities.length > 0" class="space-y-4">
        <ActivityItem
          v-for="event in activities"
          :key="event.sessionId + event.createdAt"
          :event="event" />
      </div>

      <div v-else class="text-center py-12 bg-gray-50 rounded-xl border border-dashed border-gray-300">
        <Icon name="fa7-solid:clock-rotate-left" class="text-gray-400 text-4xl mb-3" />
        <p class="text-gray-500 font-medium">No recent activity found</p>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import auth from '~/middlewares/auth'
import ActivityItem from '~/components/activity/ActivityItem.vue'
import { type AccountEvent } from '~/composables/useApi'

definePageMeta({
  layout: 'dashboard',
  middleware: auth,
})

const userStore = useUserStore()
const api = useApi()

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

const activities = ref<AccountEvent[]>([])
const pending = ref(true)

onMounted(async () => {
  try {
    const response = await api.getRecentActivities()
    activities.value = response.items || []
  } catch (error) {
    console.error('Failed to fetch recent activities:', error)
  } finally {
    pending.value = false
  }
})
</script>
