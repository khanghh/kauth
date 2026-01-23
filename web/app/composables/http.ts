import { useCookie, useRequestHeaders, useRuntimeConfig } from '#app'

export interface APIError {
  code: number
  message: string
}

// Request body encapsulation
function applyOptions(options: any = {}): any {
  const config = useRuntimeConfig()
  options.baseURL = config.public.baseUrl as string
  options.initialCache = options.initialCache ?? false
  options.headers = options.headers || {}
  options.method = options.method || 'GET'

  // Forward cookies for SSR
  const headers = useRequestHeaders(['cookie'])
  options.headers = { ...options.headers, ...headers }

  const token = useCookie('sid')
  if (token.value) {
    options.headers['X-User-Token'] = token.value
  }

  return options
}

export async function useHttp<T = any>(url: string, options: any = {}): Promise<T> {
  options = applyOptions(options)
  if (options.headers?.['Content-Type'] === 'application/x-www-form-urlencoded' && options.body) {
    options.body = new URLSearchParams(options.body).toString()
  }

  try {
    const resp = await $fetch<{ error?: any; data?: T }>(url, options)
    const response = resp
    if (!response.error) {
      return response.data as T
    } else {
      throw response.error as APIError
    }
  } catch (err: any) {
    throw err
  }
}

export function useHttpPost<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'POST',
  })
}

export function useHttpPut<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'PUT',
  })
}

export function useHttpPatch<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'PATCH',
  })
}

export function useHttpGet<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'GET',
  })
}

export function useHttpDelete<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'DELETE',
  })
}

// POST request (application/x-www-form-urlencoded)
export function useHttpPostForm<T = any>(url: string, options: any = {}): Promise<T> {
  return useHttp<T>(url, {
    ...options,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })
}

function upload<T = any>(url: string, options: any = {}): Promise<T> {
  options = applyOptions(options)
  const fullUrl = options.baseURL ? (options.baseURL + url) : url
  const formData = options.body
  const onUploadProgress = options.onUploadProgress
  const method = options.method

  return new Promise((resolve, reject) => {
    // Ensure this only runs on client side to avoid SSR issues
    if (process.server) {
      return reject(new Error('Upload not supported on server'))
    }

    const xhr = new XMLHttpRequest()
    xhr.open(method, fullUrl)

    if (options.headers) {
      Object.keys(options.headers).forEach((key) => {
        // FormData automatically sets Content-Type with boundary
        if (key.toLowerCase() !== 'content-type') {
          xhr.setRequestHeader(key, options.headers[key])
        }
      })
    }

    if (onUploadProgress) {
      xhr.upload.onprogress = onUploadProgress
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const response = JSON.parse(xhr.responseText)
          if (!response.error) {
            resolve(response.data as T)
          } else {
            reject(response.error)
          }
        } catch (e) {
          reject(e)
        }
      } else {
        reject(new Error(xhr.statusText || 'Upload failed'))
      }
    }

    xhr.onerror = () => {
      reject(new Error('Network Error'))
    }

    xhr.send(formData)
  })
}

// File upload
export function useHttpPostUpload<T = any>(url: string, options: any = {}): Promise<T> {
  return upload<T>(url, { ...options, method: 'POST' })
}

// File upload (PATCH)
export function useHttpPatchUpload<T = any>(url: string, options: any = {}): Promise<T> {
  return upload<T>(url, { ...options, method: 'PATCH' })
}
