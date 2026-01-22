import Aura from '@primeuix/themes/aura';
import path from 'path'

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  modules: [
    '@nuxtjs/tailwindcss',
    '@vueuse/nuxt',
    '@pinia/nuxt',
    '@nuxt/icon',
    '@nuxt/eslint',
  ],
  app: {
    head: {}
  },
  vite: {
    build: {
      minify: false, // Disables JS/CSS minification
    },
  },
  runtimeConfig: {
    public: {
      siteName: "{{.siteName}}"
    }
  },
  nitro: {
    prerender: {
      crawlLinks: false,
      failOnError: false,
      routes: [
        "/",
        "/change-password",
        "/2fa/challenge",
        "/2fa/otp/verify",
        "/2fa/totp/verify",
        "/error",
        "/login",
        "/register",
      ]
    },
    hooks: {
      'prerender:generate'(route) {
        if (route.skip) return
        if (!route.fileName || !route.contents) return
        const fileName = route.fileName
        console.log(`Processing: ${route.route}`)
        if (path.basename(fileName) === 'index.html' && path.dirname(fileName) !== '.') {
          const newDir = path.dirname(fileName)
          if (newDir !== '/') {
            const newBase = path.basename(newDir) + '.html'
            const newFileName = path.join(newDir, '..', newBase)
            route.fileName = newFileName
            console.log(`Renamed: ${fileName} → ${newFileName}`)
          }
        }
      },
    }
  },
  experimental: {
    payloadExtraction: false
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
