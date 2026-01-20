export function useSiteTitle(...subTitles: string[]) {
  const { siteTitle } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteTitle]
    .filter(Boolean)
    .join(' - ')
}

export function useServerVar(varName: string): Ref<string | undefined> {
  const { data } = useAsyncData<string>(varName, async () => `{{.${varName}}}`,)
  return data
}
