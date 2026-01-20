<script setup lang="ts">
const props = defineProps<{
  modelValue: string
  error?: boolean
  disabled?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'submit'): void
}>()

const inputRefs = ref<HTMLInputElement[]>([])
const digits = computed(() => {
  const arr = props.modelValue.split('')
  while (arr.length < 6) arr.push('')
  return arr.slice(0, 6)
})

const handleInput = (index: number, event: Event) => {
  const target = event.target as HTMLInputElement
  const val = target.value

  if (!/^\d*$/.test(val)) {
    // Force re-render if invalid char was typed
    target.value = digits.value[index]
    return
  }

  const newDigits = [...digits.value]
  newDigits[index] = val.slice(-1) // Take last char
  emit('update:modelValue', newDigits.join(''))

  if (val && index < 5) {
    inputRefs.value[index + 1]?.focus()
  }
}

const handleKeyDown = (index: number, event: KeyboardEvent) => {
  if (event.key === 'Backspace' && !digits.value[index] && index > 0) {
    inputRefs.value[index - 1]?.focus()
  }
  if (event.key === 'Enter') {
    emit('submit')
  }
}

const handlePaste = (event: ClipboardEvent) => {
  event.preventDefault()
  const pasteData = event.clipboardData?.getData('text') || ''
  const pastedDigits = pasteData.replace(/\D/g, '').split('').slice(0, 6)

  if (pastedDigits.length === 0) return

  const newDigits = [...digits.value]
  pastedDigits.forEach((d, i) => {
    newDigits[i] = d
  })
  emit('update:modelValue', newDigits.join(''))

  const nextIndex = Math.min(pastedDigits.length, 5)
  inputRefs.value[nextIndex]?.focus()
}

const getRef = (el: any, index: number) => {
  if (el) inputRefs.value[index] = el
}

// Focus first input on mount
onMounted(() => {
  nextTick(() => {
    inputRefs.value[0]?.focus()
  })
})
</script>

<template>
  <div class="flex justify-between gap-2">
    <input
      v-for="(digit, idx) in 6"
      :key="idx"
      type="text"
      maxlength="1"
      inputmode="numeric"
      class="w-12 h-12 border rounded-lg text-center text-xl focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
      :class="{ 'border-red-300 focus:ring-red-200': error }"
      :value="digit"
      :ref="(el) => getRef(el, idx)"
      @input="(e) => handleInput(idx, e)"
      @keydown="(e) => handleKeyDown(idx, e)"
      @paste="handlePaste"
      :disabled="disabled" />
  </div>
</template>

<style scoped>
/* Chrome, Safari, Edge, Opera */
input::-webkit-outer-spin-button,
input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

/* Firefox */
input[type=number] {
  -moz-appearance: textfield;
}
</style>
