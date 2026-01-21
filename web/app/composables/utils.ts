export function useSiteTitle(...subTitles: string[]) {
  const { siteTitle } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteTitle]
    .filter(Boolean)
    .join(' - ')
}

export function useServerVar<T extends string | number | boolean>(varName: string, defaultValue?: T): Ref<T | undefined> {
  const { data } = useAsyncData<string>(varName, async () => `{{.${varName}}}`,)

  const parsed = computed<T | undefined>(() => {
    const raw = unref(data)
    if (raw == null) return undefined

    const hint = typeof defaultValue
    if (hint === 'boolean') {
      return (raw === 'true') as T
    }
    if (hint === 'number') {
      const n = Number(raw)
      return (Number.isNaN(n) ? undefined : n) as T
    }
    if (hint === 'string') {
      return raw as T
    }

    // No explicit hint: try JSON, boolean, number, then string
    try {
      return JSON.parse(raw) as T
    } catch {
      if (raw === 'true') return true as T
      if (raw === 'false') return false as T
      const n = Number(raw)
      if (!Number.isNaN(n) && String(n) === raw) return n as T
      return raw as T
    }
  })

  return parsed
}
