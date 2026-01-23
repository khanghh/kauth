<template>
  <div v-if="show" class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
    <div class="bg-white rounded-2xl w-full max-w-sm p-6 shadow-xl">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-bold text-gray-800">Crop Your Photo</h2>
        <button class="text-gray-500 hover:text-gray-700" @click="onCancel">
          <Icon name="fa-solid:times" />
        </button>
      </div>

      <div class="w-full h-72 bg-gray-100 rounded-lg overflow-hidden mb-4 flex items-center justify-center relative">
        <img :src="image" alt="Crop Preview"
          class="max-w-full max-h-full object-contain transition-transform duration-200"
          :style="{ transform: `scale(${zoomLevel})` }" />
      </div>

      <div class="flex items-center justify-center gap-3 mt-4 mb-6">
        <Icon name="fa-solid:search-minus" class="text-gray-500" />
        <input type="range" min="1" max="3" step="0.1" v-model.number="zoomLevel"
          class="w-full h-1.5 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600" />
        <Icon name="fa-solid:search-plus" class="text-gray-500" />
      </div>

      <div class="flex justify-end gap-3">
        <button type="button" class="px-4 py-2 text-gray-700 border border-gray-300 rounded-xl hover:bg-gray-50"
          @click="onCancel" :disabled="isProcessing">
          Cancel
        </button>
        <button type="button"
          class="px-4 py-2 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 disabled:opacity-70 flex items-center"
          @click="onApply" :disabled="isProcessing">
          <Icon v-if="isProcessing" name="fa-solid:spinner" class="animate-spin mr-2" />
          {{ isProcessing ? 'Saving...' : 'Apply Crop' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

const props = defineProps<{
  show: boolean
  image: string
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'save', result: string): void
}>()

const zoomLevel = ref(1)
const isProcessing = ref(false)

// Reset zoom when dialog opens
watch(() => props.show, (newVal) => {
  if (newVal) {
    zoomLevel.value = 1
    isProcessing.value = false
  }
})

const onCancel = () => {
  if (isProcessing.value) return
  emit('close')
}

const onApply = () => {
  isProcessing.value = true
  // Simulate upload/processing delay
  setTimeout(() => {
    isProcessing.value = false
    // In a real app complexity, we'd use a canvas to actually crop the image based on zoomLevel.
    // For now, mirroring the existing behavior (simulated crop returning original image).
    emit('save', props.image)
    emit('close')
  }, 1000)
}
</script>
