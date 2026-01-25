export function useSiteTitle(...subTitles: string[]) {
  const { siteName } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteName]
    .filter(Boolean)
    .join(' - ')
}
export function useServerVar<T>(key: string, defaultValue: T): Ref<T> {
  const nuxtApp = useNuxtApp()
  const state = ref<T>(defaultValue)

  if (import.meta.server) {
    nuxtApp.payload.data ||= {}
    nuxtApp.payload.data[`s:${key}`] = `{{.${key}}}`
    return state as Ref<T>
  }

  onMounted(() => {
    const raw = nuxtApp.payload.data?.[`s:${key}`]
    state.value = parseServerVar(raw, defaultValue)
  })

  return state as Ref<T>
}

export function parseServerVar<T>(raw: unknown, defaultValue: T): T {
  if (raw == null) return defaultValue

  if (typeof raw !== 'string') return raw as T

  const trimmed = raw.trim()
  if (!trimmed || trimmed === '<no value>') return defaultValue

  // If Go template placeholders leaked through, treat as missing.
  // Examples: "{{.emailSent}}", "{{ .errorMsg }}".
  if (/^\{\{\s*\.[^}]+\}\}$/.test(trimmed)) return defaultValue

  try {
    return JSON.parse(trimmed) as T
  } catch {
    return trimmed as unknown as T
  }
}
