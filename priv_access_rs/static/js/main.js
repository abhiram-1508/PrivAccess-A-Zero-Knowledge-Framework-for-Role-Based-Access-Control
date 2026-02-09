function handleLogin(event, roleContext) {
    event.preventDefault();

    // Get button to show loading state if needed
    const form = event.target;
    const btn = form.querySelector('button');
    const originalText = btn.innerText;
    btn.innerText = "Authenticating...";
    btn.disabled = true;

    const userId = document.getElementById('user_id').value.trim();
    const authVal = document.getElementById('auth_val').value.trim();

    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            user_id: userId,
            auth_val: authVal
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                window.location.href = data.redirect;
            } else {
                alert("Login Failed: " + data.message);
                btn.innerText = originalText;
                btn.disabled = false;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert("System Error during login");
            btn.innerText = originalText;
            btn.disabled = false;
        });
}

function requestAccess(roomId) {
    // Show Modal
    const modal = document.getElementById('result-modal');
    const loader = document.getElementById('modal-loader');
    const resultDiv = document.getElementById('modal-result');

    modal.classList.remove('hidden');
    loader.classList.remove('hidden');
    resultDiv.classList.add('hidden');

    // Call API
    fetch('/api/verify_access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room_id: roomId })
    })
        .then(response => response.json())
        .then(data => {
            // Slight delay to show off the loader/ZKP calculation feeling
            setTimeout(() => {
                loader.classList.add('hidden');
                resultDiv.classList.remove('hidden');

                // Build Result HTML
                const icon = data.access_granted ? '✅' : '❌';
                const color = data.access_granted ? '#10b981' : '#ef4444';
                const title = data.access_granted ? 'Access Granted' : 'Access Denied';

                resultDiv.innerHTML = `
                <div style="font-size: 4rem; margin-bottom: 10px;">${icon}</div>
                <h2 style="color: ${color}; margin: 0;">${title}</h2>
                <p style="color: #94a3b8; margin-top: 5px;">${data.message}</p>
                <div style="margin-top: 15px; font-size: 0.8rem; opacity: 0.6;">
                    Proof Verified • Role: ${data.role}
                </div>
            `;
            }, 1500);
        })
        .catch(error => {
            loader.classList.add('hidden');
            resultDiv.classList.remove('hidden');
            resultDiv.innerHTML = `<p style="color: red">Connection Error</p>`;
        });
}

function closeModal() {
    document.getElementById('result-modal').classList.add('hidden');
}
