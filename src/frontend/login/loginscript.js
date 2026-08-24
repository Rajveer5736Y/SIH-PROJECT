const loginForm = document.getElementById("login-form");

if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("http://localhost:8000/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email, password: password })
            });
            const data = await response.json();
            if (!response.ok) {
                alert(data.detail || "Login failed");
                return;
            }
            alert("Login successful!");
            localStorage.setItem("user", JSON.stringify(data));
            window.location.href = "../dashboard-prototye/dashboard.html";
        } catch (error) {
            alert("Cannot connect to server. Make sure FastAPI is running.");
        }
    });
}