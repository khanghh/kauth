import Aura from '@primeuix/themes/aura';

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  modules: [
    '@primevue/nuxt-module',
    '@nuxtjs/tailwindcss',
    '@vueuse/nuxt',
    '@pinia/nuxt',
    '@nuxt/icon',
    '@nuxt/eslint',
  ],
  app: {
    head: {
      title: "MineViet"
    }
  },
  runtimeConfig: {
    app: {
      backendUrl: "http://localhost:3001/api"
    },
    public: {
      siteName: "MineViet"
    }
  },
  imports: {
    autoImport: true,
    dirs: [
      'stores'
    ]
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
    localApiEndpoint: '/icons',
    serverBundle: {
      collections: ['fa7-solid', 'fa7-brands'],
    },
  },
  tailwindcss: {
    exposeConfig: true,
    viewer: true,
  },
})
