<template>
  <div class="block md:hidden mb-10">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-2xl font-bold text-gray-800">Account Settings</h2>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-indigo-200 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-indigo-50 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:house" class="text-indigo-600" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Home</div>
          <div class="text-sm text-gray-500">Overview and recent updates</div>
        </div>
      </a>

      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:user" class="text-gray-700" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Personal Info</div>
          <div class="text-sm text-gray-500">Update your profile details</div>
        </div>
      </a>

      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:key" class="text-gray-700" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Change Password</div>
          <div class="text-sm text-gray-500">Keep your account secure</div>
        </div>
      </a>

      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:envelope" class="text-gray-700" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Change Email</div>
          <div class="text-sm text-gray-500">Update your contact email</div>
        </div>
      </a>

      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:mobile-screen-button" class="text-gray-700" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Two Factor Authentication</div>
          <div class="text-sm text-gray-500">Add an extra security step</div>
        </div>
      </a>

      <a
        href="#"
        class="flex items-center p-4 bg-white rounded-xl border border-gray-200 hover:border-gray-300 hover:shadow-sm transition-all">
        <div class="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-4">
          <Icon name="fa7-solid:server" class="text-gray-700" />
        </div>
        <div>
          <div class="font-medium text-gray-800">Services</div>
          <div class="text-sm text-gray-500">Manage connected services</div>
        </div>
      </a>
    </div>
  </div>
</template>
