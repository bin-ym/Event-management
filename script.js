document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
  
    loginForm.addEventListener('submit', function(event) {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const errorMessage = document.getElementById('error-message');
  
      if (username.trim() === '' || password === '') {
        event.preventDefault(); // Prevent form submission if fields are empty
        errorMessage.textContent = 'Please fill in both username and password.';
      }
    });
  });
  