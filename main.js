// ===========================================================================
// آزمایشگاه فرمت تصویر — منطق فرانت‌اند
// ===========================================================================
(function () {
  "use strict";

  const catalogGrid   = document.getElementById("catalogGrid");
  const dropzone       = document.getElementById("dropzone");
  const dzTitle        = document.getElementById("dzTitle");
  const fileInput       = document.getElementById("fileInput");
  const resultZone     = document.getElementById("resultZone");
  const thumbEl         = document.getElementById("thumb");
  const detectedExt     = document.getElementById("detectedExt");
  const detectedMethod  = document.getElementById("detectedMethod");
  const detectedStats   = document.getElementById("detectedStats");
  const detectedNote    = document.getElementById("detectedNote");
  const targetChips     = document.getElementById("targetChips");
  const convertBtn      = document.getElementById("convertBtn");
  const statusLine      = document.getElementById("statusLine");
  const downloadCard    = document.getElementById("downloadCard");
  const downloadName    = document.getElementById("downloadName");
  const downloadSizes   = document.getElementById("downloadSizes");
  const downloadBtn     = document.getElementById("downloadBtn");

  let currentToken = null;
  let currentTargets = [];
  let selectedTarget = null;
  let currentFile = null;
  let sourceSizeBytes = 0;

  const TIER_LABEL = { full: "full", extended: "extended", detect: "detect" };

  // ---------------------------------------------------------------------
  // ۱) رندر کاتالوگ ۱۸ فرمت
  // ---------------------------------------------------------------------
  fetch("/api/formats")
    .then((r) => r.json())
    .then((formats) => {
      catalogGrid.innerHTML = formats.map(cardHTML).join("");
    })
    .catch(() => {
      catalogGrid.innerHTML = `<p style="color:var(--muted)">فهرست فرمت‌ها بارگذاری نشد.</p>`;
    });

  function cardHTML(f) {
    const tier = f.tier === "extended" && !f.available ? "extended" : f.tier;
    const statusText =
      f.tier === "full" ? "SUPPORTED" :
      f.tier === "extended" ? (f.available ? "SUPPORTED" : "NEEDS PLUGIN") :
      "DETECT ONLY";
    const statusClass =
      f.tier === "full" ? "full" :
      f.tier === "extended" ? "extended" : "detect";

    return `
      <div class="card">
        <div class="stamp">${f.exts[0].replace(".", "").toUpperCase()}</div>
        <div>
          <div class="ext">${f.exts[0]}</div>
          <div class="name">${f.label}</div>
          <div class="use">${f.use}</div>
        </div>
        <div class="status ${statusClass}">${statusText}</div>
      </div>`;
  }

  // ---------------------------------------------------------------------
  // ۲) رویدادهای آپلود (کلیک / کشیدن‌ورهاکردن)
  // ---------------------------------------------------------------------
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") fileInput.click();
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });

  // ---------------------------------------------------------------------
  // ۳) ارسال فایل به /api/detect
  // ---------------------------------------------------------------------
  function handleFile(file) {
    currentFile = file;
    sourceSizeBytes = file.size;
    dzTitle.textContent = "در حال تحلیل فایل…";
    statusLine.textContent = "";
    statusLine.className = "status-line";
    downloadCard.classList.remove("show");

    // پیش‌نمایش محلی (اگر مرورگر بتواند رندرش کند)
    thumbEl.innerHTML = "";
    if (file.type.startsWith("image/")) {
      const img = document.createElement("img");
      img.src = URL.createObjectURL(file);
      thumbEl.appendChild(img);
    } else {
      thumbEl.textContent = "—";
    }

    const fd = new FormData();
    fd.append("file", file);

    fetch("/api/detect", { method: "POST", body: fd })
      .then(async (r) => {
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || "خطا در تشخیص فرمت");
        return data;
      })
      .then(renderDetected)
      .catch((err) => {
        statusLine.textContent = err.message;
        statusLine.className = "status-line error";
        dzTitle.textContent = "فایل را اینجا رها کن";
      })
      .finally(() => {
        dzTitle.textContent = "فایل را اینجا رها کن";
      });
  }

  function renderDetected(data) {
    currentToken = data.token;
    currentTargets = data.targets || [];

    detectedExt.textContent = data.label;
    detectedMethod.textContent = `${data.method} · ${data.use}`;

    const stats = [];
    if (data.width && data.height) stats.push(`${data.width}×${data.height}px`);
    if (data.size_human) stats.push(data.size_human);
    if (data.mode) stats.push(data.mode);
    detectedStats.innerHTML = stats.map((s) => `<span>${s}</span>`).join("");

    if (!data.can_convert) {
      detectedNote.style.display = "block";
      detectedNote.textContent =
        data.note ||
        "این فرمت فقط شناسایی می‌شود؛ این آزمایشگاه فعلاً نمی‌تواند از آن به فرمت دیگری تبدیل کند.";
    } else {
      detectedNote.style.display = "none";
    }

    renderTargetChips();
    resultZone.classList.add("show");
    resultZone.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function renderTargetChips() {
    selectedTarget = null;
    convertBtn.disabled = true;
    if (!currentTargets.length) {
      targetChips.innerHTML = `<span style="color:var(--muted); font-family:var(--font-mono); font-size:13px;">فرمت مقصدی برای این ورودی فعال نیست</span>`;
      return;
    }
    targetChips.innerHTML = currentTargets
      .map((t) => `<button type="button" class="chip" data-target="${t}">${t.toLowerCase()}</button>`)
      .join("");

    targetChips.querySelectorAll(".chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        targetChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        selectedTarget = chip.dataset.target;
        convertBtn.disabled = false;
      });
    });
  }

  // ---------------------------------------------------------------------
  // ۴) ارسال درخواست تبدیل
  // ---------------------------------------------------------------------
  convertBtn.addEventListener("click", () => {
    if (!selectedTarget || !currentToken) return;
    convertBtn.disabled = true;
    statusLine.textContent = "در حال تبدیل…";
    statusLine.className = "status-line";
    downloadCard.classList.remove("show");

    const fd = new FormData();
    fd.append("token", currentToken);
    fd.append("target", selectedTarget);

    fetch("/api/convert", { method: "POST", body: fd })
      .then(async (r) => {
        if (!r.ok) {
          const data = await r.json().catch(() => ({}));
          throw new Error(data.error || "تبدیل با خطا مواجه شد.");
        }
        const disposition = r.headers.get("Content-Disposition") || "";
        const match = disposition.match(/filename="?([^"]+)"?/);
        const filename = match ? match[1] : `converted.${selectedTarget.toLowerCase()}`;
        const blob = await r.blob();
        return { blob, filename };
      })
      .then(({ blob, filename }) => {
        const url = URL.createObjectURL(blob);
        downloadName.textContent = filename;
        downloadSizes.textContent = `${formatBytes(sourceSizeBytes)} → ${formatBytes(blob.size)}`;
        downloadBtn.href = url;
        downloadBtn.download = filename;
        downloadCard.classList.add("show");
        statusLine.textContent = "تبدیل با موفقیت انجام شد.";
        statusLine.className = "status-line ok";
      })
      .catch((err) => {
        statusLine.textContent = err.message;
        statusLine.className = "status-line error";
      })
      .finally(() => {
        convertBtn.disabled = false;
      });
  });

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }
})();
