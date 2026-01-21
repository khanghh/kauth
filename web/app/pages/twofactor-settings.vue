<template>
  <div class="w-full max-w-md sm:max-w-lg bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="p-8">
      <div class="text-center mb-6">
        <div class="w-24 h-24 mx-auto bg-blue-100 flex items-center justify-center rounded-full mb-6">
          <Icon name="fa-solid:shield-alt" class="text-blue-600 text-5xl" aria-hidden="true" />
        </div>
        <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-3">Two-Factor Authentication</h1>
        <p class="text-gray-600 mt-2">Manage your security verification methods</p>
      </div>

      <div v-if="errorMsg" class="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
        <Icon name="fa-solid:exclamation-circle" class="mr-2" />
        {{ errorMsg }}
      </div>

      <div v-if="successMsg" class="mb-6 p-4 rounded-lg bg-green-50 border border-green-200 text-green-700 text-sm">
        <Icon name="fa-solid:check-circle" class="mr-2" />
        {{ successMsg }}
      </div>

      <form id="twofa-form" method="POST" class="space-y-6">
        <input type="hidden" name="_csrf" :value="csrfToken"></input>

        <!-- Email Authentication -->
        <div class="p-4 border rounded-lg">
          <div class="flex items-center justify-between">
            <div class="flex items-center">
              <Icon name="fa-solid:envelope" class="fa-fw text-blue-600 text-xl mr-3" />
              <span class="text-gray-800 font-medium">Email Authentication</span>
            </div>
            <div class="relative inline-block w-12 h-6">
              <input type="checkbox" id="email-toggle" name="emailEnabled" value="true"
                class="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-2 border-gray-300 appearance-none cursor-pointer"
                :checked="emailEnabled">
              <label for="email-toggle"
                class="toggle-label block overflow-hidden h-6 rounded-full bg-gray-300 cursor-pointer"></label>
            </div>
          </div>
          <p class="text-gray-600 text-sm ml-9">
            {{ email || 'No email address configured' }}
          </p>
        </div>

        <!-- Authenticator App -->
        <div class="p-4 border rounded-lg">
          <div class="flex items-center justify-between">
            <div class="flex items-center">
              <Icon name="fa-solid:mobile-screen" class="fa-fw text-blue-600 text-xl mr-3" />
              <span class="text-gray-800 font-medium">Authenticator App</span>
            </div>
            <div class="relative inline-block w-12 h-6">
              <input type="checkbox" id="totp-toggle" name="totpEnabled" value="true"
                class="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-2 border-gray-300 appearance-none cursor-pointer"
                :checked="totpEnabled">
              <label for="totp-toggle"
                class="toggle-label block overflow-hidden h-6 rounded-full bg-gray-300 cursor-pointer"></label>
            </div>
          </div>
          <div class="ml-9">
            <a href="/2fa/totp/enroll" class="text-blue-600 hover:text-blue-500 text-sm font-medium" type="button">
              Set up authenticator
            </a>
          </div>
        </div>
      </form>

      <div class="mt-6 text-center">
        <a href="/profile" class="text-blue-600 hover:underline font-medium">
          <Icon name="fa-solid:arrow-left" class="mr-1" />
          Back to Profile
        </a>
      </div>
    </div>

    <footer class="bg-gray-50 px-6 py-4 text-center border-t border-gray-100">
      <p class="text-gray-500 text-xs sm:text-sm">
        Need help? <a href="#" class="text-blue-600 hover:underline font-medium">Contact Support</a>
      </p>
    </footer>
  </div>

  <script v-pre>
    document.querySelectorAll('.toggle-checkbox').forEach(checkbox => {
      checkbox.addEventListener('change', function () {
        document.getElementById('twofa-form').submit();
      });
    });

  </script>
</template>

<script setup lang="ts">
const errorMsg = useServerVar<string>('errorMsg', '')
const successMsg = useServerVar<string>('successMsg', '')
const csrfToken = useServerVar<string>('csrfToken', '')

const emailEnabled = useServerVar<boolean>('emailEnabled', false)
const totpEnabled = useServerVar<boolean>('totpEnabled', false)
const email = useServerVar<string>('email', '')
</script>

<style scoped>
.toggle-checkbox:checked {
  right: 0;
  border-color: #2563eb;
}

.toggle-checkbox:checked+.toggle-label {
  background-color: #2563eb;
}
</style>
