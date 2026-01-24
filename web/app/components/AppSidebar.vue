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
        <Icon name="fa7-solid:user" class="mr-3" size="20" />
        Personal Info
      </NuxtLink>

      <NuxtLink to="/change-password" :class="linkClass('/change-password')">
        <Icon name="fa7-solid:key" class="mr-3" size="20" />
        Password
      </NuxtLink>

      <NuxtLink to="/two-factor" :class="linkClass('/two-factor')">
        <Icon name="fa7-solid:shield-halved" class="mr-3" size="20" />
        Two-factor authentication
      </NuxtLink>

      <NuxtLink to="/connected-accounts" :class="linkClass('/connected-accounts')">
        <Icon name="fa7-solid:link" class="mr-3" size="20" />
        Connected accounts
      </NuxtLink>

      <NuxtLink to="/sessions" :class="linkClass('/sessions')">
        <Icon name="fa7-solid:laptop" class="mr-3" size="20" />
        Active sessions
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
  const isActive = route.path.startsWith(path)
  return [
    baseLinkClass,
    isActive
      ? 'bg-indigo-50 text-indigo-600'
      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-800',
  ]
}

</script>
