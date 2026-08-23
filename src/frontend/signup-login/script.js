

const signupForm = document.getElementById("signup_box");

let signedUpEmail = ""; // store email here after successful signup

signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    // Get values from frontend
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const role = document.querySelector('input[name="role"]:checked').value;


    // Check passwords
    if (password !== confirmPassword) {
        alert("Passwords do not match!");
        return;
    }


    try {

        const response = await fetch(
            "http://localhost:8000/auth/signup",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    name: username,
                    email: email,
                    password: password,
                    role: role
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            alert(data.detail || "Signup failed");

            return;
        }


        console.log("otp sent successful:", data);

        alert("OTP Sent To Email!");

        signedUpEmail = email; // save it for the OTP step

        // Show OTP screen
        document.getElementById("signup-view").style.display = "none";

        document.getElementById("otp-view").style.display = "flex";


    } catch (error) {

        console.error("Error:", error);

        alert(
            "Cannot connect to server. Make sure FastAPI is running."
        );

    }
});


// ---- OTP verification ----

const otpForm = document.getElementById("otp_form");

otpForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const otp = document.getElementById("otpInput").value;

    try {

        const response = await fetch(
            "http://localhost:8000/auth/verify-otp",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email: signedUpEmail,
                    otp: otp
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {

            alert(data.detail || "OTP verification failed");

            return;
        }

        console.log("Account verified:", data);

        alert("Account verified successfully!");

        window.location.href = "login.html";

    } catch (error) {

        console.error("Error:", error);

        alert(
            "Cannot connect to server. Make sure FastAPI is running."
        );

    }
});

const loginForm = document.getElementById("login_box");

if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("http://localhost:8000/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: username, password: password })
            });
            const data = await response.json();
            if (!response.ok) {
                alert(data.detail || "Login failed");
                return;
            }
            alert("Login successful!");
            localStorage.setItem("user", JSON.stringify(data));
        } catch (error) {
            alert("Cannot connect to server. Make sure FastAPI is running.");
        }
    });
}