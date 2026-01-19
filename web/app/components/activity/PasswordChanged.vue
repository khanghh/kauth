<template>
  <div
    class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-indigo-200 hover:shadow-sm transition-all">
    <div class="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mr-4">
      <Icon name="fa7-solid:key" class="text-blue-600" />
    </div>
    <div class="flex-1">
      <p class="font-medium text-gray-800">Password Changed</p>
      <p class="text-sm text-gray-500">Your account password was updated successfully</p>
    </div>
    <div class="text-right">
      <p class="text-sm text-gray-500">{{ time }}</p>
      <p class="text-xs text-blue-600 font-medium">Security</p>
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
