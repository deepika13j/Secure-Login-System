
async function getCsrfToken() {
  const response = await fetch("/api/csrf");
  const data = await response.json();

  if (!response.ok) {
    throw new Error("Unable to initialize security token.");
  }

  return data.csrfToken;
}

async function apiRequest(url, body, csrfToken) {
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });
}

function showMessage(element, message) {
  element.textContent = message;
}

// Registration
const registerForm = document.getElementById("registerForm");

if (registerForm) {
  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = document.getElementById("registerMessage");
    const button = registerForm.querySelector("button");

    button.disabled = true;
    showMessage(message, "");

    try {
      const csrfToken = await getCsrfToken();

      const response = await apiRequest(
        "/api/register",
        {
          username: document.getElementById("username").value,
          email: document.getElementById("registerEmail").value,
          password: document.getElementById("registerPassword").value
        },
        csrfToken
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Registration failed.");
      }

      window.location.href = data.redirect;
    } catch (error) {
      showMessage(message, error.message || "Unable to register.");
    } finally {
      button.disabled = false;
    }
  });
}

// Login
const loginForm = document.getElementById("loginForm");

if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = document.getElementById("loginMessage");
    const button = loginForm.querySelector("button");

    button.disabled = true;
    showMessage(message, "");

    try {
      const csrfToken = await getCsrfToken();

      const response = await apiRequest(
        "/api/login",
        {
          email: document.getElementById("loginEmail").value,
          password: document.getElementById("loginPassword").value
        },
        csrfToken
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Login failed.");
      }

      window.location.href = data.redirect;
    } catch (error) {
      showMessage(message, error.message || "Unable to log in.");
    } finally {
      button.disabled = false;
    }
  });
}

// Protected dashboard
const welcomeMessage = document.getElementById("welcomeMessage");

if (welcomeMessage) {
  async function loadDashboard() {
    try {
      const response = await fetch("/api/me", {
        credentials: "same-origin"
      });

      if (response.status === 401) {
        window.location.replace("/");
        return;
      }

      if (!response.ok) {
        throw new Error("Unable to verify your session.");
      }

      const data = await response.json();
      welcomeMessage.textContent =
        "Welcome, " + data.user.username + "!";
    } catch (error) {
      showMessage(
        document.getElementById("dashboardMessage"),
        error.message || "Unable to load dashboard."
      );
    }
  }

  loadDashboard();
}

// Logout
const logoutButton = document.getElementById("logoutButton");

if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    const message = document.getElementById("dashboardMessage");

    logoutButton.disabled = true;
    showMessage(message, "");

    try {
      const csrfToken = await getCsrfToken();
      const response = await apiRequest(
        "/api/logout",
        {},
        csrfToken
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Logout failed.");
      }

      window.location.replace("/");
    } catch (error) {
      showMessage(message, error.message || "Unable to log out.");
      logoutButton.disabled = false;
    }
  });
}
