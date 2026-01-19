<template>
  <div
    class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-green-200 hover:shadow-sm transition-all">
    <div class="w-10 h-10 rounded-full bg-green-100 flex items-center justify-center mr-4">
      <Icon name="fa7-solid:mobile-screen-button" class="text-green-600" />
    </div>
    <div class="flex-1">
      <p class="font-medium text-gray-800">2FA Device Added</p>
      <p class="text-sm text-gray-500">A new device was registered for two-factor authentication</p>
    </div>
    <div class="text-right">
      <p class="text-sm text-gray-500">{{ time }}</p>
      <p class="text-xs text-green-600 font-medium">Security</p>
    </div>
  </div>
</template>

<script setup>
defineProps({
  time: {
    type: String,
    required: true,
  },
})
</script>
