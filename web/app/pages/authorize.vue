<script setup lang="ts">
const route = useRoute()

const serviceName = computed(() => {
  const v = route.query.serviceName
  return typeof v === 'string' && v.trim() ? v : 'Dịch vụ không xác định'
})

const serviceURL = computed(() => {
  const v = route.query.serviceURL
  return typeof v === 'string' && v.trim() ? v : ''
})

const email = computed(() => {
  const v = route.query.email
  return typeof v === 'string' && v.trim() ? v : ''
})

const csrfToken = computed(() => {
  const v = route.query._csrf
  return typeof v === 'string' ? v : ''
})

const refId = ref('')
onMounted(() => {
  refId.value = `#AUTH-${Math.floor(100000 + Math.random() * 900000)}`
})

useHead({
  title: 'Cho phép truy cập',
  bodyAttrs: {
    class: 'bg-gray-50'
  }
})
</script>

<template>
  <div>
    <div class="px-6 sm:px-10 py-10">
      <div class="text-center mb-8">
        <img src="/images/mineviet_logo.png" alt="MineViet Logo" class="h-16 mx-auto mb-4 object-contain">
        <h1 class="text-3xl font-bold text-gray-800 mb-3 text-center">Cho phép truy cập</h1>
        <p class="text-lg text-gray-600 mb-6 leading-relaxed text-center">
          Xác nhận bạn muốn đăng nhập vào
          <span class="font-semibold text-blue-600">{{ serviceName }}</span>
          <template v-if="email">
            với tài khoản <span class="font-semibold text-blue-600">{{ email }}</span>
          </template>
        </p>
      </div>

      <div class="bg-gray-50 rounded-lg p-4 mb-6 border border-gray-200">
        <div class="flex items-center mb-3">
          <div class="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mr-3">
            <Icon name="fa7-solid:globe" class="text-blue-600" />
          </div>
          <div class="min-w-0">
            <p class="font-medium text-gray-800">{{ serviceName }}</p>
            <p v-if="serviceURL" class="text-sm text-gray-600 truncate">{{ serviceURL }}</p>
          </div>
        </div>

        <div class="text-sm text-gray-600">
          <p>Ứng dụng này đang yêu cầu quyền:</p>
          <ul class="mt-2 space-y-1">
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="text-green-500 mt-0.5 mr-2" />
              <span>Truy cập thông tin hồ sơ cơ bản của bạn</span>
            </li>
            <li class="flex items-start">
              <Icon name="fa7-solid:check" class="text-green-500 mt-0.5 mr-2" />
              <span>Xem địa chỉ email của bạn</span>
            </li>
          </ul>
        </div>
      </div>

      <form method="post" action="/authorize">
        <input type="hidden" name="_csrf" :value="csrfToken">

        <div class="flex flex-col sm:flex-row gap-3">
          <NuxtLink to="/"
            class="flex-1 px-5 py-3 border border-gray-300 text-gray-700 font-medium rounded-lg hover:bg-gray-50 transition flex items-center justify-center gap-2">
            <Icon name="fa7-solid:xmark" />
            Hủy
          </NuxtLink>
          <button type="submit" name="confirm" value="true"
            class="flex-1 px-5 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition flex items-center justify-center gap-2 shadow-sm">
            <Icon name="fa7-solid:check" />
            Xác nhận
          </button>
        </div>
      </form>

      <div class="mt-6 pt-6 border-t border-gray-200">
        <p class="mt-2 text-xs text-gray-400 text-center">
          Mã tham chiếu:
          <span class="font-mono">{{ refId || '#AUTH-000000' }}</span>
        </p>
        <p class="mt-4 text-xs text-gray-400 text-center">
          Bằng việc cho phép, bạn đồng ý với
          <a href="#" class="text-blue-500 hover:underline">Điều khoản dịch vụ</a>
          và
          <a href="#" class="text-blue-500 hover:underline">Chính sách bảo mật</a>
        </p>
      </div>
    </div>

    <div class="bg-gray-50 px-8 py-4 text-center">
      <form action="/logout" method="POST">
        <input type="hidden" name="_csrf" :value="csrfToken">
        <button class="text-red-600 hover:text-red-500 text-sm font-medium" type="submit">
          Đăng xuất &gt;&gt;
        </button>
      </form>
    </div>
  </div>
</template>
