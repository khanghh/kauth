<template>
  <div
    class="flex items-center justify-between bg-white border border-gray-200 rounded-xl transition duration-200 hover:border-gray-300 hover:shadow-md p-6">
    <div class="flex items-center">
      <div class="mr-4 flex items-center justify-center w-12 h-12">
        <Icon :name="iconName" :class="[iconClass, 'text-4xl']" />
      </div>
      <div>
        <div class="flex items-center gap-2">
          <div class="font-medium text-gray-800 capitalize">{{ account.provider }}</div>
          <span
            v-if="account.connected"
            class="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full inline-flex items-center">Connected</span>
        </div>
        <div class="text-sm text-gray-500">
          {{ account.connected ? (account.email || account.displayName || account.accountId) : 'Not connected' }}
        </div>
      </div>
    </div>
    <div class="flex items-center space-x-2">
      <button
        v-if="account.connected"
        type="button"
        class="text-red-600 hover:text-red-800 text-sm font-medium transition-colors"
        :disabled="processing"
        @click="$emit('disconnect')">
        {{ processing ? 'Disconnecting...' : 'Disconnect' }}
      </button>
      <button
        v-else
        type="button"
        class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium"
        :disabled="processing"
        @click="$emit('connect')">
        {{ processing ? 'Connecting...' : 'Connect' }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { OAuthAccount } from '~/composables/useApi'

defineProps<{
  account: OAuthAccount
  iconName: string
  iconClass: string
  processing: boolean
}>()

defineEmits(['connect', 'disconnect'])
</script>
