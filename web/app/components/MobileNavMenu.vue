<template>
  <div class="block md:hidden mb-10">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-2xl font-bold text-gray-800">Account Settings</h2>
    </div>
    <div class="grid grid-cols-1 gap-3">
      <NuxtLink
        href="/"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-indigo-200 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-50 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:house" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Home</div>
          <div class="text-sm text-gray-500">Overview and recent updates</div>
        </div>
      </NuxtLink>

      <NuxtLink
        href="/personal-info"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:user" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Personal Info</div>
          <div class="text-sm text-gray-500">Update your profile details</div>
        </div>
      </NuxtLink>

      <NuxtLink
        href="/change-password"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:key" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Password</div>
          <div class="text-sm text-gray-500">Manage your password</div>
        </div>
      </NuxtLink>

      <NuxtLink
        href="/two-factor"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:shield-halved" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Two Factor Authentication</div>
          <div class="text-sm text-gray-500">Protect your account with an extra security layer</div>
        </div>
      </NuxtLink>

      <NuxtLink
        href="/connected-accounts"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:mobile-screen-button" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Connected Accounts</div>
          <div class="text-sm text-gray-500">Manage your connected services</div>
        </div>
      </NuxtLink>

      <NuxtLink
        href="/sessions"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:server" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Active sessions</div>
          <div class="text-sm text-gray-500">Manage your active sessions</div>
        </div>
      </NuxtLink>
    </div>
  </div>
</template>
