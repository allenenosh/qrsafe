// DOM Elements
const fileInput = document.getElementById('fileInput');
const scanButton = document.getElementById('scanButton');
const video = document.getElementById('video');
const videoContainer = document.getElementById('videoContainer');
const output = document.getElementById('output');
const analysisResult = document.getElementById('analysisResult');
const themeToggle = document.getElementById('themeToggle');

let scanning = false;

// Event Listeners
fileInput.addEventListener('change', handleFileUpload);
scanButton.addEventListener('click', toggleScanning);
themeToggle.addEventListener('click', toggleTheme);

// File Upload Handler
function handleFileUpload(e) {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(event) {
            const img = new Image();
            img.onload = function() {
                const canvas = document.createElement('canvas');
                canvas.width = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);
                if (code) {
                    handleQRCode(code.data);
                } else {
                    output.textContent = 'No QR code found in the image.';
                }
            }
            img.src = event.target.result;
        }
        reader.readAsDataURL(file);
    }
}

// Camera Scanning
async function toggleScanning() {
    if (!scanning) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
            video.srcObject = stream;
            video.play();
            videoContainer.style.display = 'block';
            scanning = true;
            scanButton.textContent = 'Stop Scanning';
            scanQRCode();
        } catch (err) {
            console.error('Error accessing the camera:', err);
            output.textContent = 'Error accessing the camera. Please try uploading an image instead.';
        }
    } else {
        stopScanning();
    }
}

function scanQRCode() {
    if (scanning) {
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        
        if (code) {
            handleQRCode(code.data);
            stopScanning();
        } else {
            requestAnimationFrame(scanQRCode);
        }
    }
}

function stopScanning() {
    if (video.srcObject) {
        video.srcObject.getTracks().forEach(track => track.stop());
    }
    videoContainer.style.display = 'none';
    scanning = false;
    scanButton.textContent = 'Start Camera Scan';
}

// QR Code Handler
async function handleQRCode(data) {
    output.textContent = 'QR Code detected: ' + data;
    analysisResult.textContent = 'Analyzing...';
    analysisResult.className = 'analysis-result';
    
    const results = await Promise.all([
        checkUrlSafety(data),
        checkForExternalAppOpening(data),
        checkForAutoDownload(data)
    ]);

    const safetyReport = results.filter(result => result).join(' ');
    
    if (safetyReport) {
        analysisResult.textContent = safetyReport;
        analysisResult.className = 'analysis-result warning';
    } else {
        analysisResult.textContent = 'No issues detected. The QR code appears to be safe.';
        analysisResult.className = 'analysis-result safe';
    }
}

// Safety Check Functions
async function checkUrlSafety(url) {
    if (!isValidURL(url)) return 'The QR code does not contain a valid URL.';

    try {
        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key={KEY}`, {
            method: 'POST',
            body: JSON.stringify({
                client: {
                    clientId: "QRsafe",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ "url": url }]
                }
            })
        });

        const data = await response.json();
        if (data.matches && data.matches.length > 0) {
            return 'Warning: This URL has been flagged as potentially malicious.';
        }
    } catch (error) {
        console.error('Error checking URL safety:', error);
        return 'Unable to check URL safety due to an error.';
    }
}

function checkForExternalAppOpening(url) {
    const externalAppProtocols = ['mailto:', 'tel:', 'sms:', 'whatsapp:'];
    for (const protocol of externalAppProtocols) {
        if (url.startsWith(protocol)) {
            return `This link opens an external app (${protocol.slice(0, -1)}).`;
        }
    }
}

function checkForAutoDownload(url) {
    const downloadExtensions = ['.exe', '.apk', '.zip', '.pdf'];
    try {
        const parsedUrl = new URL(url);
        const pathname = parsedUrl.pathname.toLowerCase();
        for (const ext of downloadExtensions) {
            if (pathname.endsWith(ext)) {
                return `Warning: This link may trigger an auto-download (${ext} file).`;
            }
        }
    } catch (error) {
        // URL parsing failed, so it's not a valid URL
        return null;
    }
}

function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Theme Toggle
function toggleTheme() {
    document.body.toggleAttribute('data-theme');
}

// Initialize
document.body.removeAttribute('data-theme');