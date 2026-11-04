const $ = (s) => document.querySelector(s);
const stage = $('#scanStage'), video = $('#video'), result = $('#resultCard');
let stream, scannedLink = '', zoomTrack, zoomMin = 1, zoomMax = 3, zoomValue = 1, digitalZoom = 1;
let lightTimer, currentRisk = 0, currentFlags = [], currentHost = '';
let adaptiveZoomEnabled = true, autoZoomSweepStep = 0, lastAdaptiveStepTime = 0;
const sweepLevels = [1.0, 1.4, 1.8, 2.2];

const scanCanvas = document.createElement('canvas');
const scanCtx = scanCanvas.getContext('2d', { willReadFrequently: true });

function normalise(value) {
  value = value.trim();
  if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:/i.test(value)) value = 'https://' + value;
  try { return new URL(value); } catch { return null; }
}

function inspect(value) {
  const url = normalise(value);
  if (!url) { $('#cameraNote').textContent = 'That does not look like a valid web address.'; return; }
  scannedLink = url.href;
  const host = url.hostname.toLowerCase();
  const flags = [];

  const trustedBrands = ['paytm','phonepe','googlepay','gpay','amazon','flipkart','microsoft','apple','whatsapp','instagram','facebook','netflix'];

  // Handle custom protocols
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    flags.push(`This link uses a custom protocol (${url.protocol}) which may try to launch an external app.`);
    if (/^(upi|ethereum|bitcoin|sms|tel|mailto):/i.test(url.protocol)) {
      flags.push('This looks like a payment or direct action link. Never approve unexpected payment requests.');
    }

    // Custom protocols may not have a standard hostname structure
    if (!host) {
      const risk = Math.min(96, flags.length * 24 + 12);
      currentRisk = risk; currentFlags = flags; currentHost = 'Custom Protocol';
      const safe = risk < 25;
      $('#verdictTitle').textContent = safe ? 'This link looks safe' : risk < 55 ? 'Proceed with caution' : 'This link looks suspicious';
      $('#verdictLabel').textContent = safe ? 'Safety check complete' : 'Potential warning';
      $('#verdictIcon').textContent = safe ? '✓' : '!';
      $('#verdictIcon').style.color = safe ? 'var(--lime)' : 'var(--coral)';
      $('#verdictIcon').style.background = safe ? 'rgba(187,242,70,.15)' : 'rgba(255,129,120,.15)';
      $('#score').innerHTML = `${100 - risk} <small>/ 100</small>`;
      $('#score').style.color = safe ? 'var(--lime)' : 'var(--coral)';
      $('#destinationText').textContent = url.href;
      $('#checks').innerHTML = flags.map((c) => `<li class="warn">${c}</li>`).join('');
      $('#emergency').classList.toggle('hidden', risk < 45);
      updateExplainer(); updatePreview(); updateLookalike(null); updateReportCount(); saveHistory(url.href, risk);
      result.classList.remove('hidden'); result.scrollIntoView({behavior:'smooth', block:'nearest'}); result.focus({preventScroll: true});
      return;
    }
  }

  // 1. RFC 2606 & Dummy / Example / Mock Domains
  const dummyDomains = ['example.com', 'example.org', 'example.net', 'example.edu', 'test.com', 'fake.com', 'dummy.com', 'mock.com', 'sample.com', 'localhost', 'invalid'];
  const isDummy = dummyDomains.some(d => host === d || host.endsWith('.' + d));
  if (isDummy) {
    flags.push(`This link uses an example or dummy domain (${host}) which does not belong to a real live service.`);
  }

  // 2. Free app hosting & tunnel platforms
  const freeHosting = ['ngrok.io', 'ngrok-free.app', '000webhostapp.com', 'glitch.me', 'repl.co', 'loca.lt', 'trycloudflare.com', 'weebly.com', 'wixsite.com', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'surge.sh', 'github.io', 'herokuapp.com'];
  const isFreeHost = freeHosting.some(h => host === h || host.endsWith('.' + h));
  if (isFreeHost) {
    flags.push('This site is hosted on a free/temporary app hosting platform commonly used for unverified staging or phishing links.');
  }

  // 3. Shortened URLs masking destination
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'buff.ly', 'goo.gl'];
  const isShortener = shorteners.some(s => host === s || host.endsWith('.' + s));
  if (isShortener) {
    flags.push('This is a shortened link which hides its true destination address.');
  }

  // 4. Generic Service Subdomains on unverified domains
  const serviceSubdomains = /^(app|services?|portal|auth|secure|login|pay|banking|account|update|support|verify)\./i;
  if (serviceSubdomains.test(host) && !isDummy && !trustedBrands.some(b => host.endsWith(`.${b}.com`) || host.endsWith(`.${b}.in`))) {
    flags.push('The link uses a generic service subdomain (e.g. app., services.) on an unverified domain.');
  }

  // 5. Phishing & Scam Keywords
  const suspiciousWords = /login|verify|secure|wallet|gift|prize|bonus|urgent|support|account|free|services|service|auth|portal|update|pay|payment|claim|reward|upi|bill|recharge|customer|helpdesk|verification|passcode|pin|reset|kyc|refund/i;
  if (suspiciousWords.test(host + url.pathname + url.search)) {
    flags.push('The address contains words commonly used in credential phishing or fake service portals.');
  }

  // 6. Suspicious TLDs
  const suspiciousTld = /\.(xyz|top|click|gq|tk|ml|cf|test|example|invalid|shop|site|online|vip|club|work|tech|link|live|info|icu|monster)$/i;
  if (suspiciousTld.test(host)) {
    flags.push('This domain ending is frequently used in short-lived scam campaigns.');
  }

  // 7. IP Address Host
  const hasIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  if (hasIp) flags.push('The destination uses a raw IP address instead of a domain name.');

  // 8. Lookalike & Brand Mention (Levenshtein distance)
  function levenshtein(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
        }
      }
    }
    return matrix[b.length][a.length];
  }

  if (host.includes('xn--')) {
    flags.push('This domain uses Punycode (starts with xn--), which is often used in homograph attacks to create look-alike domains with non-English characters.');
  } else {
    // Check for mixed scripts or suspicious unicode characters in the decoded domain
    const hasSuspiciousUnicode = /[^\x00-\x7F]/.test(host);
    if (hasSuspiciousUnicode) {
      flags.push('This domain contains non-standard characters, which may be an attempt to visually spoof a legitimate domain (homograph attack).');
    }
  }

  let detectedBrand = null;
  const parts = host.split('.');

  for (const part of parts) {
    if (part.length < 4) continue; // Skip short parts

    // Check exact match
    const exactMatch = trustedBrands.find(b => part === b);
    if (exactMatch) {
      detectedBrand = exactMatch;
      break;
    }

    // Check typosquatting (Levenshtein distance <= 2 for strings > 5 chars, <= 1 otherwise)
    const fuzzyMatch = trustedBrands.find(b => {
      if (Math.abs(part.length - b.length) > 2) return false;
      const threshold = b.length > 5 ? 2 : 1;
      return levenshtein(part, b) > 0 && levenshtein(part, b) <= threshold;
    });

    if (fuzzyMatch) {
      flags.push(`This domain contains "${part}", which looks like a misspelling of the brand "${fuzzyMatch}". This is a common phishing technique called typosquatting.`);
      detectedBrand = fuzzyMatch;
      break; // Only flag one brand to avoid spam
    }
  }

  const brand = trustedBrands.find(name => host.includes(name));
  if (brand && host !== `${brand}.com` && !host.endsWith(`.${brand}.com`) && !host.endsWith(`.${brand}.in`)) {
    flags.push(`This domain mentions ${brand} but is not an official ${brand} domain.`);
    if (!detectedBrand) detectedBrand = brand;
  }

  // 9. URL Parameter Analysis (Open Redirect Check)
  for (const [key, paramValue] of url.searchParams) {
    if (/^https?:\/\//i.test(paramValue)) {
      flags.push(`A URL parameter ("${key}") contains another web address. This could be an open redirect trying to bounce you to a malicious site.`);
      break;
    }
  }

  // 10. Protocol Check
  if (url.protocol !== 'https:') flags.push('This site does not use an encrypted HTTPS connection.');
  if (url.href.length > 105) flags.push('The destination address is unusually long, which can hide its real purpose.');

  // High risk flags should automatically push risk to 45+
  const isHighRisk = flags.some(f =>
    f.includes('typosquatting') ||
    f.includes('custom protocol') ||
    f.includes('open redirect') ||
    f.includes('raw IP address') ||
    f.includes('dummy domain')
  );

  let risk = Math.min(96, flags.length * 24 + (url.protocol !== 'https:' ? 12 : 0));
  if (isHighRisk && risk < 45) {
      risk = 55; // Ensure it reaches "Proceed with caution" or worse
  }

  currentRisk = risk; currentFlags = flags; currentHost = host;
  const safe = risk < 25;
  $('#verdictTitle').textContent = safe ? 'This link looks safe' : risk < 55 ? 'Proceed with caution' : 'This link looks suspicious';
  $('#verdictLabel').textContent = safe ? 'Safety check complete' : 'Potential phishing warning';
  $('#verdictIcon').textContent = safe ? '✓' : '!';
  $('#verdictIcon').style.color = safe ? 'var(--lime)' : 'var(--coral)';
  $('#verdictIcon').style.background = safe ? 'rgba(187,242,70,.15)' : 'rgba(255,129,120,.15)';
  $('#score').innerHTML = `${100 - risk} <small>/ 100</small>`;
  $('#score').style.color = safe ? 'var(--lime)' : 'var(--coral)';
  $('#destinationText').textContent = url.href;
  const checks = flags.length ? flags : ['Uses an encrypted HTTPS connection.', 'No common phishing patterns were found in this address.', 'The destination was revealed before opening.'];
  $('#checks').innerHTML = checks.map((c, i) => `<li class="${flags.length ? 'warn' : ''}">${c}</li>`).join('');
  $('#emergency').classList.toggle('hidden', risk < 45);
  updateExplainer(); updatePreview(); updateLookalike(detectedBrand); updateReportCount(); saveHistory(url.href, risk);
  result.classList.remove('hidden'); result.scrollIntoView({behavior:'smooth', block:'nearest'}); result.focus({preventScroll: true});
}

let barcodeDetectorInstance = null;
async function tryBarcodeDetector(source) {
  if (!('BarcodeDetector' in window)) return null;
  try {
    if (!barcodeDetectorInstance) {
      barcodeDetectorInstance = new BarcodeDetector({ formats: ['qr_code'] });
    }
    const results = await barcodeDetectorInstance.detect(source);
    if (results && results.length > 0) {
      return { rawValue: results[0].rawValue, boundingBox: results[0].boundingBox };
    }
  } catch (e) {}
  return null;
}

function tryJsQRFromImageData(imageData) {
  if (!window.jsQR) return null;
  try {
    const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth'
    });
    if (code && code.data) {
      return { rawValue: code.data, location: code.location };
    }
  } catch (e) {}
  return null;
}

async function setZoom(value, userTriggered = true) {
  zoomValue = Math.max(zoomMin, Math.min(zoomMax, value));
  digitalZoom = zoomValue;
  if ($('#zoomSlider')) $('#zoomSlider').value = zoomValue;
  if (userTriggered) {
    const closestIdx = sweepLevels.reduce((prev, curr, idx) => 
      Math.abs(curr - zoomValue) < Math.abs(sweepLevels[prev] - zoomValue) ? idx : prev, 0);
    autoZoomSweepStep = closestIdx;
  }
  video.style.transform = `scale(${digitalZoom})`;
  try {
    if (zoomTrack?.getCapabilities?.().zoom) {
      await zoomTrack.applyConstraints({ advanced: [{ zoom: zoomValue }] });
    }
  } catch (e) {}
}

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) { $('#cameraNote').textContent = 'Camera scanning is not supported in this browser. Upload a QR image instead.'; return; }
  try {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } } });
    } catch {
      stream = await navigator.mediaDevices.getUserMedia({ video: true });
    }
    video.srcObject = stream;
    await video.play();
    stage.classList.add('camera-on');
    $('#cameraBtn').innerHTML = '<span>■</span> Stop camera';

    zoomTrack = stream.getVideoTracks()[0];
    const capabilities = zoomTrack.getCapabilities?.() || {};
    if (capabilities.zoom) {
      zoomMin = capabilities.zoom.min || 1;
      zoomMax = capabilities.zoom.max || 3;
      zoomValue = zoomMin;
      $('#cameraNote').textContent = 'Hardware & adaptive auto-zoom are active. Frame the QR code.';
    } else {
      zoomMin = 1;
      zoomMax = 3;
      zoomValue = 1;
      $('#cameraNote').textContent = 'Adaptive auto-zoom active. Point camera at the QR code.';
    }
    if ($('#zoomSlider')) {
      $('#zoomSlider').min = zoomMin;
      $('#zoomSlider').max = zoomMax;
      $('#zoomSlider').value = zoomValue;
    }
    $('#zoomControl').classList.remove('hidden');

    startLightAssist();
    detectFrame();
  } catch (error) {
    const insecure = !window.isSecureContext && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1';
    $('#cameraNote').textContent = insecure ? 'Camera access needs HTTPS or localhost. Open the site through a local server.' : 'Camera permission was not granted. Allow camera access in browser settings.';
  }
}

async function detectFrame() {
  const read = async () => {
    if (!stream) return;
    if (video.videoWidth > 0 && video.videoHeight > 0) {
      try {
        const width = video.videoWidth, height = video.videoHeight;
        scanCanvas.width = width;
        scanCanvas.height = height;

        const crop = 1 / digitalZoom;
        const sw = width * crop, sh = height * crop;
        const sx = (width - sw) / 2, sy = (height - sh) / 2;

        scanCtx.drawImage(video, sx, sy, sw, sh, 0, 0, width, height);

        // Pass 1: Full frame
        let result = await tryBarcodeDetector(scanCanvas);
        if (!result) {
          const imgData = scanCtx.getImageData(0, 0, width, height);
          result = tryJsQRFromImageData(imgData);
        }

        // Pass 2: Center region (65% width/height)
        if (!result) {
          const cropW = Math.floor(width * 0.65);
          const cropH = Math.floor(height * 0.65);
          const cropX = Math.floor((width - cropW) / 2);
          const cropY = Math.floor((height - cropH) / 2);
          const cropData = scanCtx.getImageData(cropX, cropY, cropW, cropH);
          result = tryJsQRFromImageData(cropData);
        }

        if (result && result.rawValue) {
          stopCamera();
          inspect(result.rawValue);
          return;
        }

        // Adaptive Auto-Zoom Sweep
        if (adaptiveZoomEnabled) {
          const now = Date.now();
          if (now - lastAdaptiveStepTime > 1400) {
            lastAdaptiveStepTime = now;
            autoZoomSweepStep = (autoZoomSweepStep + 1) % sweepLevels.length;
            const targetZoom = Math.min(zoomMax, Math.max(zoomMin, sweepLevels[autoZoomSweepStep]));
            setZoom(targetZoom, false);
          }
        }
      } catch (err) {
        console.error('Frame detection error:', err);
      }
    }
    if (stream) requestAnimationFrame(read);
  };
  read();
}

function startLightAssist() {
  clearInterval(lightTimer);
  const canvas = document.createElement('canvas');
  canvas.width = 32; canvas.height = 24;
  const context = canvas.getContext('2d', { willReadFrequently: true });
  lightTimer = setInterval(() => {
    if (!stream || !video.videoWidth) return;
    context.drawImage(video, 0, 0, 32, 24);
    const pixels = context.getImageData(0, 0, 32, 24).data;
    let sum = 0;
    for (let i = 0; i < pixels.length; i += 4) sum += .2126 * pixels[i] + .7152 * pixels[i + 1] + .0722 * pixels[i + 2];
    const light = sum / (pixels.length / 4);
    const brightness = Math.max(.72, Math.min(1.32, 1 + (128 - light) / 255));
    video.style.filter = `brightness(${brightness}) contrast(1.05)`;
  }, 350);
}

function stopCamera() {
  clearInterval(lightTimer);
  video.style.transform = '';
  video.style.filter = '';
  stream?.getTracks().forEach(t => t.stop());
  stream = null;
  zoomTrack = null;
  $('#zoomControl').classList.add('hidden');
  video.srcObject = null;
  stage.classList.remove('camera-on');
  $('#cameraBtn').innerHTML = '<span>⌁</span> Scan with camera';
}

$('#cameraBtn').onclick = () => stream ? stopCamera() : startCamera();
if ($('#zoomSlider')) $('#zoomSlider').oninput = e => setZoom(Number(e.target.value), true);
if ($('#zoomIn')) $('#zoomIn').onclick = () => setZoom(zoomValue + .25, true);
if ($('#zoomOut')) $('#zoomOut').onclick = () => setZoom(zoomValue - .25, true);

const adaptiveBtn = $('#adaptiveZoomBtn');
if (adaptiveBtn) {
  adaptiveBtn.onclick = () => {
    adaptiveZoomEnabled = !adaptiveZoomEnabled;
    adaptiveBtn.classList.toggle('active', adaptiveZoomEnabled);
    adaptiveBtn.textContent = adaptiveZoomEnabled ? '✦ Auto Zoom' : '◇ Auto Zoom';
    if (!adaptiveZoomEnabled) setZoom(1, true);
  };
}

async function readImage(file) {
  if (!file?.type.startsWith('image/')) {
    $('#cameraNote').textContent = 'Please choose an image containing a QR code.';
    return;
  }
  $('#cameraNote').textContent = 'Reading QR code…';
  try {
    let rawValue;

    if ('BarcodeDetector' in window) {
      try {
        const bitmap = await createImageBitmap(file);
        const code = await tryBarcodeDetector(bitmap);
        rawValue = code?.rawValue;
      } catch (e) {}
    }

    if (!rawValue && window.jsQR) {
      const image = await createImageBitmap(file);
      const imgCanvas = document.createElement('canvas');
      imgCanvas.width = image.width;
      imgCanvas.height = image.height;
      const ctx = imgCanvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(image, 0, 0);

      // Pass 1: Full resolution
      let imgData = ctx.getImageData(0, 0, imgCanvas.width, imgCanvas.height);
      let res = tryJsQRFromImageData(imgData);
      if (res) rawValue = res.rawValue;

      // Pass 2: Downscaled (max 800px)
      if (!rawValue) {
        const scale = 800 / Math.max(image.width, image.height);
        const sW = Math.max(1, Math.floor(image.width * scale));
        const sH = Math.max(1, Math.floor(image.height * scale));
        const sCanvas = document.createElement('canvas');
        sCanvas.width = sW;
        sCanvas.height = sH;
        const sCtx = sCanvas.getContext('2d', { willReadFrequently: true });
        sCtx.drawImage(image, 0, 0, sW, sH);
        res = tryJsQRFromImageData(sCtx.getImageData(0, 0, sW, sH));
        if (res) rawValue = res.rawValue;
      }

      // Pass 3: Center 60% crop
      if (!rawValue) {
        const cW = Math.floor(imgCanvas.width * 0.6);
        const cH = Math.floor(imgCanvas.height * 0.6);
        const cX = Math.floor((imgCanvas.width - cW) / 2);
        const cY = Math.floor((imgCanvas.height - cH) / 2);
        res = tryJsQRFromImageData(ctx.getImageData(cX, cY, cW, cH));
        if (res) rawValue = res.rawValue;
      }
    }

    if (rawValue) inspect(rawValue);
    else $('#cameraNote').textContent = 'No QR code was found. Try a sharper, uncropped image.';
  } catch (error) {
    console.error(error);
    $('#cameraNote').textContent = 'We could not read that image. Try a PNG or JPG file.';
  }
}

$('#fileInput').onchange = e => readImage(e.target.files[0]);
['dragenter','dragover'].forEach(type => stage.addEventListener(type, e => { e.preventDefault(); stage.classList.add('drag-over'); }));
['dragleave','drop'].forEach(type => stage.addEventListener(type, e => { e.preventDefault(); stage.classList.remove('drag-over'); }));
stage.addEventListener('drop', e => readImage(e.dataTransfer.files[0]));
['dragenter','dragover','dragleave','drop'].forEach(type => document.addEventListener(type, e => e.preventDefault()));
stage.addEventListener('click', () => { if (!stream) $('#fileInput').click(); });
stage.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && !stream) { e.preventDefault(); $('#fileInput').click(); } });
$('#checkBtn').onclick = () => inspect($('#manualUrl').value);
$('#manualUrl').onkeydown = e => { if (e.key === 'Enter') inspect(e.target.value); };
$('#copyBtn').onclick = async () => { await navigator.clipboard.writeText(scannedLink); $('#toast').classList.add('show'); setTimeout(() => $('#toast').classList.remove('show'), 1800); };
$('#openBtn').onclick = () => window.open(scannedLink, '_blank', 'noopener,noreferrer');
$('#scanAnother').onclick = () => { result.classList.add('hidden'); $('#manualUrl').value = ''; $('#manualUrl').focus(); };
document.querySelectorAll('.sample-btn').forEach(btn => {
  btn.onclick = () => {
    const url = btn.dataset.url;
    $('#manualUrl').value = url;
    inspect(url);
  };
});

const key = 'scansure-history-v4', reportKey = 'scansure-reports-v4';

// Completely clear all old storage & legacy pdf records on load
try {
  localStorage.clear();
} catch (e) {}

function updateExplainer() {
  const lang = $('#language').value;
  const unsafe = currentRisk >= 45;
  const messages = {
    en: unsafe ? 'This link has scam-like signals. Do not log in, pay, or share an OTP unless you verify the address independently.' : 'No major scam signals were found. Still confirm the sender before entering personal or payment details.',
    hi: unsafe ? 'इस लिंक में धोखाधड़ी के संकेत हैं। स्वतंत्र रूप से जांचे बिना लॉग इन, भुगतान या OTP साझा न करें।' : 'कोई बड़ा जोखिम नहीं मिला। फिर भी निजी या भुगतान विवरण देने से पहले प्रेषक की पुष्टि करें।',
    ta: unsafe ? 'இந்த இணைப்பில் மோசடி அறிகுறிகள் உள்ளன. தனியாக சரிபார்க்காமல் உள்நுழையவோ, பணம் செலுத்தவோ, OTP பகிரவோ வேண்டாம்.' : 'பெரிய மோசடி அறிகுறிகள் இல்லை. தனிப்பட்ட தகவலை வழங்க முன் அனுப்புநரை உறுதிப்படுத்துங்கள்.'
  };
  $('#explainerText').textContent = messages[lang];
}
function updatePreview() {
  const favicon = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(currentHost)}&sz=32`;
  $('#previewText').innerHTML = `<img src="${favicon}" width="16" height="16" alt="" style="vertical-align:middle;margin-right:6px;border-radius:3px"> <strong>${currentHost}</strong><br>Preview generated without opening the destination page.`;
}
function updateLookalike(brand) {
  $('#lookalikeText').textContent = brand ? `${currentHost} uses “${brand}” in its name. Check that it is an official ${brand} domain.` : 'No known major-brand word was detected in this domain.';
}
function getHistory() { try { return JSON.parse(localStorage.getItem(key)) || []; } catch { return []; } }
function renderHistory() {
  const items = getHistory();
  $('#historyList').innerHTML = items.length ? items.map(item => `<li><span>${item.url}</span><small>${item.risk >= 45 ? 'High risk' : item.risk >= 25 ? 'Caution' : 'Looks safe'}</small></li>`).join('') : '<li><span>No links checked yet.</span></li>';
}
function saveHistory(url, risk) {
  const items = getHistory().filter(item => item.url !== url);
  items.unshift({url, risk, time:Date.now()});
  localStorage.setItem(key, JSON.stringify(items.slice(0, 6))); renderHistory();
}
function reportId() { return new URL(scannedLink).hostname; }
function getReports() { try { return JSON.parse(localStorage.getItem(reportKey)) || {}; } catch { return {}; } }
function updateReportCount() { const reports = getReports(); const count = reports[reportId()] || 0; $('#reportCount').textContent = `${count} local report${count === 1 ? '' : 's'}`; $('#reportBtn').disabled = false; $('#reportBtn').textContent = 'Report as scam'; }
$('#language').onchange = updateExplainer;
$('#previewBtn').onclick = updatePreview;
$('#reportBtn').onclick = () => { const reports = getReports(); reports[reportId()] = (reports[reportId()] || 0) + 1; localStorage.setItem(reportKey, JSON.stringify(reports)); updateReportCount(); $('#reportBtn').disabled = true; $('#reportBtn').textContent = 'Reported'; };
$('#clearHistory').onclick = () => { localStorage.removeItem(key); renderHistory(); };
renderHistory();
