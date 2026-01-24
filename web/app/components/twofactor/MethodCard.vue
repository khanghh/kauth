<template>
  <div
    class="p-6 bg-white border border-gray-200 rounded-xl transition-all duration-200 hover:border-gray-300 hover:shadow-md">
    <div class="flex items-start justify-between">
      <div class="flex items-start space-x-4">
        <div :class="`w-12 h-12 rounded-full flex items-center justify-center ${iconBgClass}`">
          <Icon :name="iconName" :class="`${iconColorClass} text-xl`" />
        </div>
        <div>
          <h3 class="font-bold text-gray-800 text-lg mb-1">{{ title }}</h3>
          <div class="flex items-center text-sm text-gray-500">
            <slot name="description"></slot>
          </div>
        </div>
      </div>

      <div class="flex items-center space-x-4">
        <label class="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            class="sr-only peer"
            :checked="enabled"
            :disabled="disabled"
            @change="$emit('toggle', $event)" />
          <div
            class="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600 peer-disabled:opacity-50 peer-disabled:cursor-not-allowed">
          </div>
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string
  iconName: string
  iconBgClass: string
  iconColorClass: string
  enabled: boolean
  disabled?: boolean
}>()

defineEmits(['toggle'])
</script>
