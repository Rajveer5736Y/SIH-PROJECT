document.getElementById("myvideo").playbackRate = 0.5;


const signupForm = document.getElementById("inner_box");

signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    // Get values from frontend
    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;


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
                    password: password
                })
            }
        );


        const data = await response.json();


        if (!response.ok) {

            alert(data.detail || "Signup failed");

            return;
        }


        console.log("Signup successful:", data);

        alert("Signup successful!");


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