<script setup lang="ts">
import VerifyEmailForm from '~/components/twofactor/VerifyEmailForm.vue'
import VerifySmsForm from '~/components/twofactor/VerifySmsForm.vue'
import VerifyTotpForm from '~/components/twofactor/VerifyTotpForm.vue'

const route = useRoute()
const method = computed(() => route.params.method as string)

const cid = computed(() => route.query.cid as string || '')
const email = computed(() => route.query.email as string || '')
const phone = computed(() => route.query.phone as string || '')
const csrfToken = computed(() => route.query._csrf as string || '')

const goBack = () => {
  navigateTo({
    path: '/2fa/challenge',
    query: route.query
  })
}

const pageTitle = computed(() => {
  switch (method.value) {
    case 'email': return 'Xác minh Email'
    case 'sms': return 'Xác minh SMS'
    case 'totp': return 'Xác minh Authenticator'
    default: return 'Xác minh 2FA'
  }
})

useHead({
  title: pageTitle,
  bodyAttrs: {
    class: 'bg-gray-50'
  }
})
</script>

<template>
  <div>
    <div class="p-8">
      <div class="text-center mb-4">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto object-contain">
      </div>

      <VerifyEmailForm
        v-if="method === 'email'"
        :cid="cid"
        :csrf-token="csrfToken"
        :email="email"
        @back="goBack" />
      <VerifySmsForm
        v-if="method === 'sms'"
        :cid="cid"
        :csrf-token="csrfToken"
        :phone="phone"
        @back="goBack" />
      <VerifyTotpForm
        v-if="method === 'totp'"
        :cid="cid"
        :csrf-token="csrfToken"
        @back="goBack" />

      <div v-if="!['email', 'sms', 'totp'].includes(method)" class="text-center text-red-600">
        Phương thức xác thực không hợp lệ.
        <div class="mt-4">
          <button @click="goBack" class="text-blue-600 hover:underline">Quay lại</button>
        </div>
      </div>
    </div>
    <!-- Footer -->
    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <form action="/logout" method="POST">
        <input type="hidden" name="_csrf" :value="csrfToken" />
        <button type="submit"
          class="text-red-600 hover:text-red-500 text-sm font-medium flex items-center justify-center gap-1 mx-auto">
          <span>Đăng xuất</span>
          <Icon name="fa7-solid:right-from-bracket" />
        </button>
      </form>
    </footer>
  </div>
</template>
