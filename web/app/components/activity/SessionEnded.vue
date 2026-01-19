<template>
  <div
    class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-red-200 hover:shadow-sm transition-all">
    <div class="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center mr-4">
      <Icon name="fa7-solid:right-from-bracket" class="text-red-600" />
    </div>
    <div class="flex-1">
      <p class="font-medium text-gray-800">Session Ended</p>
      <p class="text-sm text-gray-500">You logged out from an active session</p>
    </div>
    <div class="text-right">
      <p class="text-sm text-gray-500">{{ time }}</p>
      <p class="text-xs text-red-600 font-medium">Security</p>
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
