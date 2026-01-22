<template>
  <aside :class="['w-80 bg-transparent p-6', props.class]">
    <a href="/" class="flex items-center mb-10">
      <img
        :src="brandLogoUrl"
        :alt="brandName"
        class="mr-3 h-12 w-12 object-contain"
        decoding="async"
        loading="lazy" />
      <div>
        <div href="/" class="text-2xl text-gray-800 flex items-center">
          <span class="font-bold">{{ brandName }}</span>
          <span>&nbsp;Account</span>
        </div>
        <p class="text-gray-500 text-sm mt-1">{{ subtitle }}</p>
      </div>
    </a>

    <nav class="space-y-2">
      <NuxtLink to="/" :class="linkClass('/')">
        <Icon name="fa7-solid:house" class="mr-3" size="20" />
        Home
      </NuxtLink>

      <NuxtLink to="/personal-info" :class="linkClass('/personal-info')">
        <Icon name="fa-solid:user" class="mr-3" size="20" />
        Personal Info
      </NuxtLink>

      <NuxtLink to="/change-password" :class="linkClass('/change-password')">
        <Icon name="fa-solid:key" class="mr-3" size="20" />
        Change Password
      </NuxtLink>

      <NuxtLink to="/twofactor-settings" :class="linkClass('/twofactor-settings')">
        <Icon name="fa7-solid:mobile-screen-button" class="mr-3" size="20" />
        Two Factor Authentication
      </NuxtLink>

      <NuxtLink to="/" :class="linkClass('/services')">
        <Icon name="fa-solid:server" class="mr-3" size="20" />
        Services
      </NuxtLink>
    </nav>
  </aside>
</template>

<script setup lang="ts">
const route = useRoute()

const props = defineProps({
  brandName: {
    type: String,
    default: 'KAuth',
  },
  brandLogoUrl: {
    type: String,
    default: '/images/logo.png'
  },
  subtitle: {
    type: String,
    default: 'Manage Your Account',
  },
  class: {
    type: [Array, String],
    default: '',
  },
})

const baseLinkClass =
  'flex items-center px-5 py-4 rounded-2xl text-base font-medium transition'

const linkClass = (path: string) => {
  const isActive = route.path === path
  return [
    baseLinkClass,
    isActive
      ? 'bg-indigo-50 text-indigo-600'
      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-800',
  ]
}

</script>
