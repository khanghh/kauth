<template>
  <div class="max-w-4xl mx-auto">
    <div class="text-center mb-12">
      <div class="relative w-32 h-32 mx-auto mb-6">
        <div
          class="w-full h-full rounded-full border-4 border-blue-100 overflow-hidden flex items-center justify-center bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg">
          <img
            v-if="avatarMainOk"
            :src="user.avatarUrl"
            alt="Profile"
            class="w-full h-full object-cover"
            @error="avatarMainOk = false">
          <span v-else class="text-white text-5xl font-bold select-none">{{ userInitial }}</span>
        </div>
      </div>

      <h1 class="text-3xl font-bold text-gray-800 mb-2">{{ user.displayName }}</h1>

      <p class="text-gray-600 text-lg inline-flex items-center justify-center">
        <Icon name="fa7-solid:envelope" class="mr-2" />
        {{ user.email }}
      </p>
    </div>

    <MobileNavMenu />
    <RecentActivitySection />
  </div>

</template>

<script setup>
import { computed, ref } from 'vue'

const userInitial = computed(() => (user.displayName?.trim()?.[0] ?? 'U').toUpperCase())

// Sidebar nav items are rendered directly inside the SidebarNav component

const user = ref({
  displayName: 'MineViet Official',
  role: 'Admin',
  email: 'minevietofficial@gmail.com',
  avatarUrl: 'https://lh3.googleusercontent.com/a/ACg8ocJ3AGOwBK1bdrsn2LDW8lFbNk6tjGnK9d6qk_GUaN2Nzw47Y7qt=s96-c',
})

const avatarMainOk = ref(true)
definePageMeta({
  layout: 'dashboard',
  middleware: 'auth'
})
</script>
