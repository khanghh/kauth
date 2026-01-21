<template>
  <div class="text-center max-w-md">
    <div class="text-9xl font-bold mb-4 text-red-600">{{ errorConfig.code }}</div>
    <h1 class="text-3xl font-bold text-gray-800 mb-2">{{ errorConfig.title }}</h1>
    <p class="text-lg text-gray-600 mb-4">{{ errorConfig.message }}</p>
    <div class="flex justify-center space-x-4">
      <button @click="handleError"
        class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
        <i class="fas fa-home mr-2"></i>
        Return to Home
      </button>
      <a href="mailto:admin@mineviet.com"
        class="bg-gray-300 hover:bg-gray-400 text-gray-700 font-medium py-3 px-4 rounded-lg transition duration-200 border border-gray-300">
        <i class="far fa-envelope"></i>
        Contact Support
      </a>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const statusCode = useServerVar<string>("statusCode")
const statusMessage = useServerVar<string>("statusMessage")

const errorConfig = computed(() => {
  if (statusCode.value === '404') {
    return {
      code: '404',
      title: 'Page Not Found',
      message: 'Sorry, the page you’re looking for doesn’t exist.',
    }
  } else if (statusCode.value === '403') {
    return {
      code: '403',
      title: 'Forbidden',
      message: 'You don’t have permission to access this page.',
    }
  } else if (statusCode.value === '500') {
    return {
      code: '500',
      title: 'Internal Server Error',
      message: 'Oops! Something went wrong. Please try again later.',
    }
  } else {
    return {
      code: statusCode || 'Error',
      title: statusMessage || 'An Error Occurred',
      message: 'Something went wrong. Please try again.',
    }
  }
})

const handleError = () => {
  clearError({ redirect: '/' })
}
</script>
