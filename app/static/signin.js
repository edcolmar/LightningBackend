const signinButton = document.getElementById('signin-button');
const qrButton = document.querySelector('#signin .qr-button');
const weblnButton = document.querySelector('#signin .webln-button');
const loginModal = new bootstrap.Modal('#signin');
let signinActive = false;

let lnurl = "";

async function signin() {

    if(signinActive)
        return;

    signinActive = true;

    loginModal.show();

    document.getElementById('signin').addEventListener('hidden.bs.modal', (event) => {
        signinButton.disabled = false;
        signinButton.innerHTML = '<i class="bi bi-currency-bitcoin"></i> Sign in';
        signinActive = false;
    });

    signinButton.disabled = true;
    signinButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span><span class="sr-only"> Connecting...</span>`;

    const request = await fetch('/auth');
    const result = await request.json();

    document.querySelector('#signin .qr-link').href = "lightning:" + result.lnurl;
    lnurl = result.lnurl;

    document.getElementById("qr_image").src="/generate_qr/${result.lnurl}";

    // The response only contains the lnrul as text.
    // Request the QR code as well - later.

    if (window.webln) {
        weblnButton.href = "lightning:" + result.lnurl;
        weblnButton.classList.remove('d-none');
    } else {
        qrButton.classList.add('d-none');
        startQr();
    }

    startPolling(1000, signInSuccess);
}

function signInSuccess() {
    console.log('signin success');
    signinActive = false;
    window.location.reload();

}

function loading() {
    document.querySelector('#signin .modal-footer').classList.remove('d-none');
}

async function startQr() {
    loading();

    document.querySelector('#signin  .qr-container').classList.remove('d-none');
}

function startWebLN() {
    loading();
    weblnButton.disabled = true;
}

async function isSignedIn() {
    const response = await fetch('/me');
    const result = await response.json();
    console.log(result);

    return result.user != null;
}

function startPolling(timeout, onSuccess) {
    console.log(signinActive);
    
    if(!signinActive)
        return;
        
    setTimeout(async function () {
        const result = await isSignedIn();

        if (!result) {
            startPolling(timeout, onSuccess);
        } else {
            onSuccess();
        }
    }, timeout);
}