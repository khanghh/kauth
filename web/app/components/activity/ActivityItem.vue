<template>
  <div
    class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-indigo-200 hover:shadow-sm transition-all">
    <div :class="['w-10 h-10 rounded-full flex items-center justify-center mr-4', config.bgColor]">
      <Icon :name="config.icon" :class="config.iconColor" />
    </div>
    <div class="flex-1">
      <p class="font-medium text-gray-800">{{ config.title }}</p>
      <p class="text-sm text-gray-500">
        <template v-if="config.descriptionParts">
          <span>{{ config.descriptionParts.before }}</span>
          <span class="font-semibold text-gray-700">{{ config.descriptionParts.bold }}</span>
          <span>{{ config.descriptionParts.after }}</span>
        </template>
        <template v-else>
          {{ config.description }}
        </template>
      </p>
    </div>
    <div class="text-right">
      <p class="text-sm text-gray-500">{{ timeAgo }}</p>
      <p class="text-xs font-medium text-gray-500">{{ event.ip }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useTimeAgo } from '@vueuse/core'
import { type AccountEvent, AccountEventType } from '~/composables/useApi'

const props = defineProps<{
  event: AccountEvent
}>()

const timeAgo = useTimeAgo(props.event.createdAt)

const config = computed(() => {
  const service = props.event.service
  const serviceName = service || 'KAuth'
  const targetTxt = service ? `to ${service}` : 'to your account'
  const targetTxtFrom = service ? `from ${service}` : 'from your account'
  const targetTxtFor = service ? `for ${service}` : 'for your account'
  const methodTxt = props.event.authMethod ? ` via ${props.event.authMethod}` : ''
  const challengeTxt = props.event.challengeType ? `${props.event.challengeType} ` : ''

  switch (props.event.eventType) {
    case AccountEventType.LoginSuccess:
      return {
        icon: 'fa7-solid:right-to-bracket',
        bgColor: 'bg-green-100',
        iconColor: 'text-green-600',
        title: 'Login Success',
        description: `Successfully logged in ${targetTxt}${methodTxt}`
      }
    case AccountEventType.LoginFailure:
      return {
        icon: 'fa7-solid:triangle-exclamation',
        bgColor: 'bg-red-100',
        iconColor: 'text-red-600',
        title: 'Login Failed',
        description: `Failed login attempt ${targetTxt}${methodTxt}${props.event.reason ? ': ' + props.event.reason : ''} (${props.event.ip})`
      }
    case AccountEventType.UserLogout:
      return {
        icon: 'fa7-solid:right-from-bracket',
        bgColor: 'bg-red-100',
        iconColor: 'text-red-600',
        title: 'Logged Out',
        description: `Signed out ${targetTxtFrom}`
      }
    case AccountEventType.ServiceAuthorized:
      return {
        icon: 'mdi:shield-check',
        bgColor: 'bg-indigo-100',
        iconColor: 'text-indigo-600',
        title: 'Service Authorized',
        descriptionParts: {
          before: 'Authorized access to service ',
          bold: serviceName,
          after: ''
        }
      }
    case AccountEventType.TwoFAChallengeCreated:
      return {
        icon: 'fa7-solid:shield-halved',
        bgColor: 'bg-yellow-100',
        iconColor: 'text-yellow-600',
        title: '2FA Challenge',
        description: `A ${challengeTxt}challenge was requested ${targetTxtFor}`
      }
    case AccountEventType.TwoFAAttemptSuccess:
      return {
        icon: 'fa7-solid:check-double',
        bgColor: 'bg-green-100',
        iconColor: 'text-green-600',
        title: '2FA Success',
        description: `${challengeTxt}verification successful ${targetTxtFor}`
      }
    case AccountEventType.TwoFAAttemptFailure:
      return {
        icon: 'fa7-solid:xmark',
        bgColor: 'bg-red-100',
        iconColor: 'text-red-600',
        title: '2FA Failed',
        description: `${challengeTxt}verification failed ${targetTxtFor}${props.event.reason ? ': ' + props.event.reason : ''}`
      }
    default:
      return {
        icon: 'fa7-solid:bell',
        bgColor: 'bg-blue-100',
        iconColor: 'text-blue-600',
        title: 'Account Activity',
        description: 'Recent activity on your account'
      }
  }
})
</script>
