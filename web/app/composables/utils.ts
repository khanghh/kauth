export function useSiteTitle(...subTitles: string[]) {
  const { siteName } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteName]
    .filter(Boolean)
    .join(' - ')
}

export function useServerVar<T>(key: string, defaultValue: T): Ref<T> {
  const nuxtApp = useNuxtApp()

  // inject template variable value
  if (import.meta.server) {
    nuxtApp.payload.data ||= {}
    nuxtApp.payload.data[`s:${key}`] = `{{.${key}}}`
  }

  return computed(() => {
    if (import.meta.server) {
      return defaultValue
    }
    const raw = nuxtApp.payload.data?.[`s:${key}`]
    try {
      return JSON.parse(raw) as T
    } catch {
      return raw as unknown as T
    }
  })
}
