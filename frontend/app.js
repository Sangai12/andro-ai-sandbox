const checkBackendButton = document.getElementById("checkBackendBtn");
const backendStatus = document.getElementById("backendStatus");

async function checkBackendStatus() {
    backendStatus.textContent = "Checking backend...";
    backendStatus.style.color = "#facc15";

    try {
        const response = await fetch("http://127.0.0.1:8000/health");

        if (!response.ok) {
            throw new Error("Backend returned an error response.");
        }

        const data = await response.json();

        backendStatus.textContent = `Backend connected: ${data.status} (${data.service})`;
        backendStatus.style.color = "#22c55e";
    } catch (error) {
        backendStatus.textContent = "Backend not reachable. Please make sure FastAPI is running.";
        backendStatus.style.color = "#ef4444";
    }
}

if (checkBackendButton) {
    checkBackendButton.addEventListener("click", checkBackendStatus);
}
