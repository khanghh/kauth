export function useSiteTitle(...subTitles: string[]) {
  const { siteTitle } = useRuntimeConfig().public

  return [...subTitles.filter(Boolean), siteTitle]
    .filter(Boolean)
    .join(' - ')
}
