<template>
  <div class="error-container">
    <h1 class="error-title">Unauthorized Access</h1>
    <p class="error-message">You are not authorized to view this content.</p>
    <div class="error-actions">
      <NuxtLink to="/" class="link">Return to Homepage</NuxtLink>
      <NuxtLink to="/login" class="link">Login</NuxtLink>
    </div>
  </div>
</template>

<style scoped>
.error-container {
  max-width: 600px;
  margin: 0 auto;
  padding: 40px;
  text-align: center;
  background-color: #f8f9fa;
  border-radius: 8px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

.error-title {
  font-size: 36px;
  color: #dc3545;
  margin-bottom: 20px;
}

.error-message {
  font-size: 18px;
  color: #6c757d;
  margin-bottom: 30px;
}

.error-actions {
  display: flex;
  justify-content: center;
}

.link {
  padding: 10px 20px;
  margin: 0 10px;
  font-size: 16px;
  color: #fff;
  background-color: #007bff;
  border: none;
  border-radius: 5px;
  text-decoration: none;
  cursor: pointer;
  transition: background-color 0.3s ease;
}

.link:hover {
  background-color: #0056b3;
}
</style>
