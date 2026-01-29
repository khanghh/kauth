<template>
  <div v-if="show" class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
    <div class="bg-white rounded-2xl w-full max-w-sm p-6 shadow-xl">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-bold text-gray-800">Crop Your Photo</h2>
        <button class="text-gray-500 hover:text-gray-700" @click="onCancel">
          <Icon name="fa7-solid:times" />
        </button>
      </div>

      <div class="w-full h-72 bg-gray-100 rounded-lg overflow-hidden mb-4 flex items-center justify-center relative">
        <img :src="image" alt="Crop Preview"
          class="max-w-full max-h-full object-contain transition-transform duration-200"
          :style="{ transform: `scale(${zoomLevel})` }" />
      </div>

      <div class="flex items-center justify-center gap-3 mt-4 mb-6">
        <Icon name="fa7-solid:search-minus" class="text-gray-500" />
        <input type="range" min="1" max="3" step="0.1" v-model.number="zoomLevel"
          class="w-full h-1.5 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-indigo-600" />
        <Icon name="fa7-solid:search-plus" class="text-gray-500" />
      </div>

      <div class="flex justify-end gap-3">
        <button type="button" class="px-4 py-2 text-gray-700 border border-gray-300 rounded-xl hover:bg-gray-50"
          @click="onCancel" :disabled="isProcessing">
          Cancel
        </button>
        <button type="button"
          class="px-4 py-2 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 disabled:opacity-70 flex items-center"
          @click="onApply" :disabled="isProcessing">
          <Icon v-if="isProcessing" name="fa7-solid:spinner" class="animate-spin mr-2" />
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
  (e: 'save', result: File): void
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

const canvasSize = 400

const onApply = async () => {
  if (!props.image) return
  isProcessing.value = true

  try {
    const img = new Image()
    img.crossOrigin = 'anonymous'
    const dataUrl = props.image

    await new Promise<void>((resolve, reject) => {
      img.onload = () => resolve()
      img.onerror = () => reject(new Error('Failed to load image'))
      img.src = dataUrl
    })

    const canvas = document.createElement('canvas')
    canvas.width = canvasSize
    canvas.height = canvasSize
    const ctx = canvas.getContext('2d')!

    // Compute source rect from original image based on zoomLevel.
    const srcW = Math.max(1, img.naturalWidth / zoomLevel.value)
    const srcH = Math.max(1, img.naturalHeight / zoomLevel.value)
    const srcX = Math.max(0, (img.naturalWidth - srcW) / 2)
    const srcY = Math.max(0, (img.naturalHeight - srcH) / 2)

    ctx.drawImage(img, srcX, srcY, srcW, srcH, 0, 0, canvasSize, canvasSize)

    await new Promise<void>((resolve, reject) => {
      canvas.toBlob((blob) => {
        if (!blob) return reject(new Error('Failed to create blob'))
        const file = new File([blob], 'avatar.png', { type: 'image/png' })
        emit('save', file)
        resolve()
      }, 'image/png')
    })

  } catch (err) {
    console.error('Crop failed', err)
  } finally {
    isProcessing.value = false
    emit('close')
  }
}
</script>
