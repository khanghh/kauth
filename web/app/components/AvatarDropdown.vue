<template>
  <div class="p-4 sm:p-6 flex justify-end">
    <div ref="dropdownRoot" class="relative">
      <button
        type="button"
        class="flex items-center space-x-3 focus:outline-none group"
        @click.stop="toggleDropdown">

        <div class="p-1 rounded-full transition-colors group-hover:bg-gray-200">
          <div
            class="relative w-10 h-10 rounded-full bg-transparent flex items-center justify-center text-gray-700 font-bold">
            <img
              v-if="avatarOk"
              :src="user.picture"
              alt="Profile"
              class="w-full h-full rounded-full object-cover"
              @error="avatarOk = false">
            <span v-else class="text-2xl leading-none select-none">{{ userInitial }}</span>
          </div>
        </div>
      </button>

      <div
        class="absolute right-0 mt-3 w-64 bg-white rounded-xl shadow-xl border border-gray-200 py-2 z-50 transition-all duration-200"
        :class="isOpen ? 'opacity-100 translate-y-0 pointer-events-auto' : 'opacity-0 -translate-y-2 pointer-events-none'"
        role="menu"
        aria-label="User menu"
        @click.stop>
        <div class="px-4 py-3 border-b border-gray-100">
          <p class="font-medium text-gray-800">{{ user.fullName }}</p>
          <p class="text-sm text-gray-500 truncate">{{ user.email }}</p>
        </div>

        <NuxtLink href="/"
          class="flex items-center px-4 py-3 text-gray-700 hover:bg-gray-50 hover:text-gray-800 transition-colors">
          <Icon name="fa7-solid:house" class="mr-3 text-gray-400" />
          Home
        </NuxtLink>

        <NuxtLink href="/personal-info"
          class="flex items-center px-4 py-3 text-gray-700 hover:bg-gray-50 hover:text-gray-800 transition-colors">
          <Icon name="fa7-solid:user" class="mr-3 text-gray-400" />
          My Profile
        </NuxtLink>

        <div class="border-t border-gray-100 my-2"></div>

        <form :action="logoutAction" method="POST">
          <button
            type="submit"
            class="flex items-center w-full px-4 py-3 text-red-600 hover:bg-red-50 hover:text-red-700 transition-colors">
            <Icon name="fa7-solid:right-from-bracket" class="mr-3" />
            Log out
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onClickOutside } from '@vueuse/core'

const userStore = useUserStore()

const user = computed(() => {
  if (userStore.user) {
    return userStore.user
  }
  return {} as UserInfo
})

const props = defineProps({
  logoutAction: {
    type: String,
    default: '/logout',
  },
  csrfToken: {
    type: String,
    default: '',
  },
})

const userInitial = computed(() => (user.value.username?.trim()?.[0] ?? 'U').toUpperCase())

const isOpen = ref(false)
const dropdownRoot = ref(null)

const avatarOk = ref(true)

function toggleDropdown() {
  isOpen.value = !isOpen.value
}

function closeDropdown() {
  isOpen.value = false
}

onClickOutside(dropdownRoot, closeDropdown)
</script>
