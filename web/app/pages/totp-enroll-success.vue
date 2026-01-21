<template>
  <div class="w-full max-w-md sm:max-w-lg bg-white shadow-lg rounded-2xl overflow-hidden">
    <div class="px-6 sm:px-10 py-10 text-center">
      <div class="w-24 h-24 mx-auto bg-green-100 flex items-center justify-center rounded-full mb-4">
        <Icon name="fa-solid:circle-check" class="text-green-500 text-5xl" aria-hidden="true" />
      </div>
      <h1 class="text-3xl font-bold text-gray-800 mb-4">Setup Complete</h1>
      <p class="text-gray-600 mt-2">
        Your authenticator app has been successfully enrolled. You can now use it to verify sign-ins and secure your
        account.
      </p>

      <div class="mt-6 flex flex-col sm:flex-row gap-3 justify-center">
        <a href="/profile"
          class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition duration-200">
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
</template>
