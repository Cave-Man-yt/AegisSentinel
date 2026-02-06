/**
 * GenAI Sentinel - Login Handler
 * Simple frontend logic for authentication
 */

// API Configuration
const API_URL = 'http://localhost:8000';

// Get DOM elements
const loginModal = document.getElementById('loginModal');
const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const errorMessage = document.getElementById('errorMessage');

// Show error message
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
    errorMessage.classList.add('shake');
    
    // Remove shake animation after it completes
    setTimeout(() => {
        errorMessage.classList.remove('shake');
    }, 500);
    
    // Auto-hide error after 5 seconds
    setTimeout(() => {
        errorMessage.style.display = 'none';
    }, 5000);
}

// Hide error message
function hideError() {
    errorMessage.style.display = 'none';
    errorMessage.textContent = '';
}

// Close login modal
function closeLoginModal() {
    loginModal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

// Open login modal
function openLoginModal() {
    loginModal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    hideError();
}

// Handle login form submission
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault(); // Prevent page refresh
    
    // Hide any previous errors
    hideError();
    
    // Get form values
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    // Basic validation
    if (!username || !password) {
        showError('Please enter both username and password');
        return;
    }
    
    // Disable submit button during request
    const submitButton = loginForm.querySelector('button[type="submit"]');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<span>AUTHENTICATING...</span>';
    
    try {
        // Send login request to backend
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // ✅ Login successful
            console.log('✅ Login successful');
            
            // Store username in localStorage (optional)
            localStorage.setItem('username', username);
            localStorage.setItem('isAuthenticated', 'true');
            
            // Close modal
            closeLoginModal();
            
            // Clear form
            loginForm.reset();
            
            // Show success notification (optional)
            alert('Login successful! Welcome to GenAI Sentinel.');
            
        } else {
            // ❌ Login failed
            showError(data.message || 'Invalid username or password');
        }
        
    } catch (error) {
        // Network or server error
        console.error('Login error:', error);
        showError('Connection error. Please check if the server is running.');
    } finally {
        // Re-enable submit button
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
    }
});

// Show login modal when page loads (for testing)
window.addEventListener('DOMContentLoaded', () => {
    // Check if user is already logged in
    const isAuthenticated = localStorage.getItem('isAuthenticated');
    
    if (!isAuthenticated) {
        // Show login modal
        openLoginModal();
    }
});

// Optional: Add login icon click handler
const loginIcon = document.getElementById('loginIcon');
if (loginIcon) {
    loginIcon.addEventListener('click', () => {
        openLoginModal();
    });
}

// Optional: Logout functionality
function logout() {
    localStorage.removeItem('username');
    localStorage.removeItem('isAuthenticated');
    openLoginModal();
}

// Add logout to user icon (optional)
const userIcon = document.getElementById('userIcon');
if (userIcon) {
    userIcon.addEventListener('click', () => {
        const username = localStorage.getItem('username');
        if (username) {
            const confirmLogout = confirm(`Logged in as: ${username}\n\nDo you want to logout?`);
            if (confirmLogout) {
                logout();
            }
        }
    });
}
