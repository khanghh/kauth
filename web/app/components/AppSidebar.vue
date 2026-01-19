<template>
  <aside :class="['w-80 bg-transparent p-6', props.class]">
    <a href="/" class="flex items-center mb-10">
      <img
        :src="brandLogoUrl"
        alt="MineViet logo"
        class="mr-3 h-12 w-12 object-contain"
        decoding="async"
        loading="lazy" />
      <div>
        <div href="/" class="text-2xl text-gray-800 flex items-center">
          <span class="font-bold">{{ brandName }}</span>
          <span>&nbsp;Account</span>
        </div>
        <p class="text-gray-500 text-sm mt-1">{{ subtitle }}</p>
      </div>
    </a>

    <nav class="space-y-2">
      <a href="#" class="flex items-center px-5 py-4 rounded-2xl bg-indigo-50 text-indigo-600 text-base font-medium">
        <Icon name="fa7-solid:house" class="mr-3" size="20" />
        Home
      </a>
      <a href="#"
        class="flex items-center px-5 py-4 rounded-2xl text-gray-600 hover:bg-gray-50 hover:text-gray-800 text-base font-medium">
        <Icon name="fa7-solid:user" class="mr-3" size="20" />
        Personal Info
      </a>
      <a href="#"
        class="flex items-center px-5 py-4 rounded-2xl text-gray-600 hover:bg-gray-50 hover:text-gray-800 text-base font-medium">
        <Icon name="fa7-solid:key" class="mr-3" size="20" />
        Change Password
      </a>
      <a href="#"
        class="flex items-center px-5 py-4 rounded-2xl text-gray-600 hover:bg-gray-50 hover:text-gray-800 text-base font-medium">
        <Icon name="fa7-solid:envelope" class="mr-3" size="20" />
        Change Email
      </a>
      <a href="#"
        class="flex items-center px-5 py-4 rounded-2xl text-gray-600 hover:bg-gray-50 hover:text-gray-800 text-base font-medium">
        <Icon name="fa7-solid:mobile-screen-button" class="mr-3" size="20" />
        Two Factor Authentication
      </a>
      <a href="#"
        class="flex items-center px-5 py-4 rounded-2xl text-gray-600 hover:bg-gray-50 hover:text-gray-800 text-base font-medium">
        <Icon name="fa7-solid:server" class="mr-3" size="20" />
        Services
      </a>
    </nav>
  </aside>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  brandName: {
    type: String,
    default: 'MineViet',
  },
  brandLogoUrl: {
    type: String,
    default: '/images/mineviet_logo.png'
  },
  subtitle: {
    type: String,
    default: 'Manage Your Account',
  },
  class: {
    type: [Array, String],
    default: '',
  },
})

</script>
