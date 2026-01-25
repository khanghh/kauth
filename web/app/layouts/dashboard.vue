<template>
  <div class="bg-gray-50 min-h-screen font-sans">
    <div class="flex flex-col md:flex-row min-h-screen">
      <AppSidebar class="hidden md:block" />
      <!-- Main Content -->
      <div class="flex-1 flex flex-col">
        <AvatarDropdown />

        <!-- Main body -->
        <main class="flex-1 p-4 sm:p-6 lg:p-8">
          <slot></slot>
        </main>
      </div>
    </div>
  </div>
</template>
