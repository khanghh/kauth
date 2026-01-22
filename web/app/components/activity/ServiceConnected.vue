<template>
  <div
    class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-yellow-200 hover:shadow-sm transition-all">
    <div class="w-10 h-10 rounded-full bg-yellow-100 flex items-center justify-center mr-4">
      <Icon name="fa7-solid:server" class="text-yellow-600" />
    </div>
    <div class="flex-1">
      <p class="font-medium text-gray-800">Service Connected</p>
      <p class="text-sm text-gray-500">A new service was linked to your account</p>
    </div>
    <div class="text-right">
      <p class="text-sm text-gray-500">{{ time }}</p>
      <p class="text-xs text-yellow-600 font-medium">Services</p>
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
