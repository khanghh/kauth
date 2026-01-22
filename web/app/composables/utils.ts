export function useSiteTitle(...subTitles: string[]) {
  const { siteName } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteName]
    .filter(Boolean)
    .join(' - ')
}

export function useServerVar<T>(key: string, defaultValue: T): Ref<T> {
  const nuxtApp = useNuxtApp()

  // Inject template variable value for the client to read during hydration.
  // On the server we *never* want to treat unresolved placeholders as truthy values.
  if (import.meta.server) {
    nuxtApp.payload.data ||= {}
    nuxtApp.payload.data[`s:${key}`] = `{{.${key}}}`
    return ref(defaultValue) as Ref<T>
  }

  const raw = nuxtApp.payload.data?.[`s:${key}`]
  const parsed = parseServerVar(raw, defaultValue)
  return ref(parsed) as Ref<T>
}

function parseServerVar<T>(raw: unknown, defaultValue: T): T {
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
