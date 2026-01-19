import Aura from '@primeuix/themes/aura';

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  modules: [
    '@primevue/nuxt-module',
    '@nuxtjs/tailwindcss',
    '@nuxt/icon',
    '@nuxt/eslint',
  ],
  app: {
    head: {}
  },
  imports: {
    autoImport: true
  },
  css: [
    '~/assets/css/index.scss',
  ],
  eslint: {
    config: {
      stylistic: true,
    },
  },
  primevue: {
    options: {
      theme: {
        preset: Aura
      }
    }
  },
  icon: {
    serverBundle: {
      collections: ['fa7-solid', 'fa7-brands'],
    },
  },
  tailwindcss: {
    exposeConfig: true,
    viewer: true,
  },
})
