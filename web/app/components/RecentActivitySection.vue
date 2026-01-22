<template>
  <section class="mt-12">
    <div class="flex items-center justify-between mb-6">
      <h2 class="text-2xl font-bold text-gray-800">Recent Activity</h2>
      <a href="#" class="text-sm text-indigo-600 hover:text-indigo-700 font-medium inline-flex items-center">
        View All
        <Icon name="fa7-solid:arrow-right" class="ml-1" />
      </a>
    </div>

    <div class="space-y-4">
      <ActivityPasswordChanged time="Today, 10:30 AM" />
      <ActivityTwoFaDeviceAdded time="Yesterday, 14:20 PM" />
      <ActivityProfileUpdated time="2 days ago" />
      <ActivitySessionEnded time="3 days ago" />
      <ActivityServiceConnected time="1 week ago" />
    </div>
  </section>
</template>
