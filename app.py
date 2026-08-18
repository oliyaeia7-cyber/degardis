# -*- coding: utf-8 -*-
"""
آزمایشگاه فرمت تصویر — بک‌اند
------------------------------------------------
یک سرویس Flask برای:
  1) شناسایی فرمت واقعیِ یک فایل تصویری از روی محتوای آن
     (نه فقط پسوند نام فایل) با استفاده از تحلیل سرآیند/هدر فایل
     (Magic Bytes) و کتابخانه‌ی Pillow.
  2) تبدیل تصویر ورودی به فرمت خروجیِ انتخابیِ کاربر.

نکته‌ی صادقانه: این موتور «تشخیص فرمت» یک مدل یادگیری‌عمیق نیست؛
چون فرمت فایل در چند بایت اول آن به‌صورت قطعی مشخص می‌شود، تحلیل
هدر فایل (که همین‌جا پیاده‌سازی شده) از هر مدل احتمالاتی هوش
مصنوعی هم دقیق‌تر و سریع‌تر است. برای فرمت‌هایی که Pillow آن‌ها را
نمی‌شناسد (RAW، DNG، XCF و ...) هم یک لایه‌ی تشخیص مبتنی بر
امضای باینری فایل نوشته شده تا حداقل «شناسایی» برای همه‌ی ۱۸ فرمت
جدول کار کند، حتی اگر «تبدیل» برای همه‌شان ممکن نباشد.
"""

import functools
import io
import os
import struct
import time
import uuid
from datetime import datetime, timezone

from flask import (
    Flask, request, jsonify, send_file, render_template, abort,
    send_from_directory, session, redirect, url_for,
)
from PIL import Image, ImageOps

# ---------------------------------------------------------------------------
# تنظیمات هویت سایت — از متغیرهای محیطی (برای دیپلوی روی Render)
# ---------------------------------------------------------------------------
SITE_NAME = "دگردیس"
SITE_TAGLINE = "آزمایشگاه فرمت تصویر"
SITE_URL = os.environ.get("SITE_URL", "https://degardis.onrender.com").rstrip("/")
SITE_DESCRIPTION = "دگردیس فرمت واقعی هر فایل تصویری را از روی محتوای آن تشخیص می‌دهد و بین ۱۸ فرمت مختلف تبدیل می‌کند."

# ---------------------------------------------------------------------------
# فعال‌سازی افزونه‌های اختیاری Pillow (در صورت نصب بودن)
# ---------------------------------------------------------------------------
HEIF_AVAILABLE = False
AVIF_AVAILABLE = False

try:
    import pillow_heif  # pip install pillow-heif
    pillow_heif.register_heif_opener()
    HEIF_AVAILABLE = True
except Exception:
    HEIF_AVAILABLE = False

try:
    import pillow_avif  # noqa: F401  (pip install pillow-avif-plugin) - فقط import کافیست
    AVIF_AVAILABLE = True
except Exception:
    AVIF_AVAILABLE = False

app = Flask(__name__, template_folder=".", static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # حداکثر ۲۰ مگابایت

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# کلید نشست (session) — حتماً روی Render از طریق متغیر محیطی SECRET_KEY
# مقداردهی شود، وگرنه با هر ری‌استارت سرور همه‌ی نشست‌های ادمین باطل می‌شوند.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-insecure-secret-change-me")

# رمز پنل ادمین — این مقدار هرگز در کد نوشته نمی‌شود؛ فقط از متغیر محیطی
# ADMIN_PASSWORD خوانده می‌شود. این متغیر را در Render → Environment تنظیم کن.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# ---------------------------------------------------------------------------
# آمار درون‌حافظه‌ای برای نمایش در پنل ادمین
# (برای سادگی؛ با ری‌استارت سرور صفر می‌شود — برای ماندگاری واقعی نیاز به دیتابیس است)
# ---------------------------------------------------------------------------
STATS = {
    "started_at": time.time(),
    "detections": 0,
    "conversions": 0,
    "detect_by_format": {},
    "convert_by_target": {},
    "recent_activity": [],  # هر آیتم: {time, action, detail}
}


def log_activity(action: str, detail: str):
    STATS["recent_activity"].insert(0, {
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "action": action,
        "detail": detail,
    })
    del STATS["recent_activity"][30:]


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped


# چون همه فایل‌های پروژه (از جمله app.py و requirements.txt) کنار هم در ریشه
# هستند، مسیر پیش‌فرض static غیرفعال شده (static_folder=None) و به‌جایش این
# مسیر دستی تعریف شده که فقط پسوندهای امن (css/js/تصاویر/فونت) را از ریشه‌ی
# پروژه سرو می‌کند؛ درخواست هر فایل دیگری (مثل .py، .txt، .md) ۴۰۴ می‌شود.
ALLOWED_STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".gif", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".map",
}


@app.route("/static/<path:filename>", endpoint="static")
def static_files(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_STATIC_EXTENSIONS:
        abort(404)
    return send_from_directory(BASE_DIR, filename)

# ---------------------------------------------------------------------------
# رجیستری کامل ۱۸ فرمت خواسته‌شده
# ---------------------------------------------------------------------------
# tier:
#   full      -> شناسایی + تبدیل ورودی/خروجی به‌صورت کامل توسط Pillow
#   extended  -> شناسایی + تبدیل، مشروط به نصب بودن کتابخانه‌ی اختیاری
#   in_only   -> فقط به‌عنوان ورودی قابل تبدیل است (خروجی پشتیبانی نمی‌شود)
#   out_only  -> فقط به‌عنوان خروجی قابل تولید است
#   detect    -> فقط شناسایی می‌شود؛ تبدیل نیازمند ابزار تخصصی جداگانه است

FORMATS = {
    "JPEG": dict(label="JPEG", exts=[".jpg", ".jpeg"], mime="image/jpeg",
                 use="عکس‌های معمولی و وب", tier="full", save_as="JPEG"),
    "PNG": dict(label="PNG", exts=[".png"], mime="image/png",
                use="تصاویر با کیفیت و شفافیت", tier="full", save_as="PNG"),
    "WEBP": dict(label="WebP", exts=[".webp"], mime="image/webp",
                 use="وب، حجم کم و کیفیت خوب", tier="full", save_as="WEBP"),
    "GIF": dict(label="GIF", exts=[".gif"], mime="image/gif",
                use="تصاویر متحرک ساده", tier="full", save_as="GIF"),
    "BMP": dict(label="BMP", exts=[".bmp"], mime="image/bmp",
                use="تصاویر Bitmap ویندوز", tier="full", save_as="BMP"),
    "TIFF": dict(label="TIFF", exts=[".tif", ".tiff"], mime="image/tiff",
                 use="چاپ و تصاویر با کیفیت بالا", tier="full", save_as="TIFF"),
    "SVG": dict(label="SVG", exts=[".svg"], mime="image/svg+xml",
                use="تصاویر برداری و آیکون", tier="detect",
                note="برداری است؛ تبدیل رستر↔وکتور نیازمند موتور رندر جداست."),
    "AVIF": dict(label="AVIF", exts=[".avif"], mime="image/avif",
                 use="وب، حجم بسیار کم", tier="extended", save_as="AVIF",
                 available=AVIF_AVAILABLE, pip="pillow-avif-plugin"),
    "HEIF": dict(label="HEIF", exts=[".heif"], mime="image/heif",
                 use="تصاویر با فشرده‌سازی بالا", tier="extended", save_as="HEIF",
                 available=HEIF_AVAILABLE, pip="pillow-heif"),
    "HEIC": dict(label="HEIC", exts=[".heic"], mime="image/heic",
                 use="فرمت رایج دوربین آیفون", tier="extended", save_as="HEIF",
                 available=HEIF_AVAILABLE, pip="pillow-heif"),
    "ICO": dict(label="ICO", exts=[".ico"], mime="image/x-icon",
                use="آیکون ویندوز", tier="full", save_as="ICO"),
    "ICNS": dict(label="ICNS", exts=[".icns"], mime="image/icns",
                 use="آیکون macOS", tier="full", save_as="ICNS"),
    "RAW": dict(label="RAW", exts=[".raw"], mime="image/x-raw",
                use="تصاویر خام دوربین", tier="detect",
                note="فرمت‌های RAW وابسته به سازنده‌ی دوربین‌اند؛ نیازمند rawpy/libraw."),
    "DNG": dict(label="DNG", exts=[".dng"], mime="image/x-adobe-dng",
                use="فرمت RAW شرکت Adobe", tier="detect",
                note="بر پایه‌ی TIFF است اما داده‌ی خام دارد؛ نیازمند rawpy/libraw."),
    "PSD": dict(label="PSD", exts=[".psd"], mime="image/vnd.adobe.photoshop",
                use="پروژه Photoshop", tier="in_only", save_as=None,
                note="فقط تصویر ترکیب‌شده (flatten) خوانده می‌شود، بدون لایه‌ها."),
    "XCF": dict(label="XCF", exts=[".xcf"], mime="image/x-xcf",
                use="پروژه GIMP", tier="detect",
                note="نیازمند GIMP یا کتابخانه‌ی تخصصی برای خواندن لایه‌هاست."),
    "EPS": dict(label="EPS", exts=[".eps"], mime="application/postscript",
                use="گرافیک برداری و چاپ", tier="detect",
                note="رندر آن روی سرور نیازمند نصب Ghostscript است."),
    "PDF": dict(label="PDF", exts=[".pdf"], mime="application/pdf",
                use="اسناد و گرافیک؛ می‌تواند شامل تصاویر باشد", tier="out_only",
                save_as="PDF", note="به‌عنوان ورودی فقط شناسایی می‌شود؛ رستر کردن صفحه نیازمند PyMuPDF است."),
}

# فرمت‌هایی که واقعاً می‌توان یک تصویر را با Pillow به آن‌ها *تبدیل* کرد
CONVERTIBLE_TARGETS = [
    key for key, f in FORMATS.items()
    if f["tier"] in ("full", "out_only") or (f["tier"] == "extended" and f.get("available"))
]

# فرمت‌هایی که می‌توان از آن‌ها به‌عنوان *ورودی* برای تبدیل استفاده کرد
CONVERTIBLE_SOURCES = [
    key for key, f in FORMATS.items()
    if f["tier"] in ("full", "in_only") or (f["tier"] == "extended" and f.get("available"))
]


# ---------------------------------------------------------------------------
# لایه‌ی تشخیص فرمت بر اساس امضای باینری (Magic Bytes)
# این تابع مستقل از پسوند نام فایل کار می‌کند.
# ---------------------------------------------------------------------------
def sniff_by_signature(head: bytes, sample_text: bytes) -> str | None:
    if head[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if head[:2] == b"BM":
        return "BMP"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        # TIFF یا DNG (که بر پایه‌ی TIFF است)
        if b"DNG" in sample_text or b"Adobe" in sample_text and b"DNG" in sample_text:
            return "DNG"
        return "TIFF"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WEBP"
    if head[:4] == b"\x00\x00\x01\x00":
        return "ICO"
    if head[:4] == b"icns":
        return "ICNS"
    if head[:4] == b"8BPS":
        return "PSD"
    if head[:4] == b"%PDF":
        return "PDF"
    if head[:4] == b"gimp" and b"xcf" in head[:16]:
        return "XCF"
    if head[:2] == b"%!" or b"EPSF" in sample_text[:2048]:
        return "EPS"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1"):
            return "HEIC" if brand in (b"heic", b"heix") else "HEIF"
        if brand in (b"avif", b"avis"):
            return "AVIF"
    if sample_text.strip().startswith(b"<?xml") and b"<svg" in sample_text[:1024]:
        return "SVG"
    if sample_text.strip().startswith(b"<svg"):
        return "SVG"
    return None


def detect_format(data: bytes, filename: str) -> tuple[str | None, str]:
    """
    فرمت واقعی فایل را برمی‌گرداند.
    خروجی: (کلید فرمت در FORMATS یا None، توضیح روش تشخیص)
    """
    # ۱) اول تلاش با Pillow (دقیق‌ترین روش برای فرمت‌های شناخته‌شده)
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
        with Image.open(io.BytesIO(data)) as img:
            pillow_fmt = (img.format or "").upper()
            mapping = {
                "JPEG": "JPEG", "MPO": "JPEG", "PNG": "PNG", "GIF": "GIF",
                "BMP": "BMP", "TIFF": "TIFF", "WEBP": "WEBP", "ICO": "ICO",
                "ICNS": "ICNS", "PSD": "PSD", "HEIF": "HEIF", "AVIF": "AVIF",
            }
            key = mapping.get(pillow_fmt)
            if key:
                # اگر پسوند فایل صراحتاً heic بود، همان برچسب را نشان بده
                if key == "HEIF" and os.path.splitext(filename)[1].lower() == ".heic":
                    key = "HEIC"
                return key, "تحلیل ساختار داخلی فایل توسط Pillow"
    except Exception:
        pass

    # ۲) در غیر این صورت، تحلیل امضای باینری (برای فرمت‌هایی که Pillow نمی‌شناسد)
    head = data[:64]
    sample_text = data[:4096]
    key = sniff_by_signature(head, sample_text)
    if key:
        return key, "تحلیل امضای باینری فایل (Magic Bytes)"

    # ۳) آخرین راه: پسوند نام فایل
    ext = os.path.splitext(filename)[1].lower()
    for k, f in FORMATS.items():
        if ext in f["exts"]:
            return k, "بر اساس پسوند نام فایل (محتوا قابل تشخیص نبود)"

    return None, "فرمت ناشناخته"


def format_size(n: int) -> str:
    for unit in ["B", "KB", "MB"]:
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------------------
# مسیرها
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template(
        "index.html",
        site_name=SITE_NAME,
        site_tagline=SITE_TAGLINE,
        site_url=SITE_URL,
        site_description=SITE_DESCRIPTION,
    )


@app.route("/robots.txt")
def robots_txt():
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /admin\n"
        "Disallow: /admin/\n\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    return app.response_class(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url>\n"
        f"    <loc>{SITE_URL}/</loc>\n"
        "    <changefreq>weekly</changefreq>\n"
        "    <priority>1.0</priority>\n"
        "  </url>\n"
        "</urlset>\n"
    )
    return app.response_class(body, mimetype="application/xml")


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if not ADMIN_PASSWORD:
            error = "رمز پنل ادمین تنظیم نشده است. متغیر محیطی ADMIN_PASSWORD را در Render تنظیم کن."
        elif request.form.get("password") == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            error = "رمز عبور اشتباه است."
    return render_template("admin_login.html", site_name=SITE_NAME, error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    uptime_seconds = int(time.time() - STATS["started_at"])
    hours, rem = divmod(uptime_seconds, 3600)
    minutes, _ = divmod(rem, 60)
    top_detected = sorted(STATS["detect_by_format"].items(), key=lambda x: -x[1])[:8]
    top_converted = sorted(STATS["convert_by_target"].items(), key=lambda x: -x[1])[:8]
    return render_template(
        "admin_dashboard.html",
        site_name=SITE_NAME,
        detections=STATS["detections"],
        conversions=STATS["conversions"],
        uptime=f"{hours} ساعت و {minutes} دقیقه",
        top_detected=top_detected,
        top_converted=top_converted,
        recent_activity=STATS["recent_activity"],
        admin_password_set=bool(ADMIN_PASSWORD),
        secret_key_set=os.environ.get("SECRET_KEY") is not None,
        heif_available=HEIF_AVAILABLE,
        avif_available=AVIF_AVAILABLE,
        total_formats=len(FORMATS),
    )


@app.route("/api/formats")
def api_formats():
    """فهرست کامل ۱۸ فرمت برای رندر بخش کاتالوگ در فرانت‌اند."""
    out = []
    for key, f in FORMATS.items():
        out.append({
            "key": key,
            "label": f["label"],
            "ext": f["exts"][0],
            "exts": f["exts"],
            "use": f["use"],
            "tier": f["tier"],
            "available": f.get("available", True),
            "note": f.get("note", ""),
        })
    return jsonify(out)


@app.route("/api/detect", methods=["POST"])
def api_detect():
    if "file" not in request.files:
        return jsonify(error="هیچ فایلی ارسال نشده است."), 400
    file = request.files["file"]
    data = file.read()
    if not data:
        return jsonify(error="فایل خالی است."), 400

    key, method = detect_format(data, file.filename or "")
    if not key:
        return jsonify(error="نتوانستیم فرمت این فایل را شناسایی کنیم."), 422

    STATS["detections"] += 1
    STATS["detect_by_format"][key] = STATS["detect_by_format"].get(key, 0) + 1
    log_activity("تشخیص", f"{file.filename or 'فایل'} → {key}")

    info = FORMATS[key]
    width = height = mode = None
    can_be_source = key in CONVERTIBLE_SOURCES
    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            mode = img.mode
    except Exception:
        pass

    targets = [t for t in CONVERTIBLE_TARGETS if t != key]

    token = uuid.uuid4().hex
    _CACHE[token] = data
    _CACHE_NAMES[token] = file.filename or f"upload{info['exts'][0]}"

    return jsonify({
        "token": token,
        "detected": key,
        "label": info["label"],
        "use": info["use"],
        "method": method,
        "tier": info["tier"],
        "note": info.get("note", ""),
        "size_bytes": len(data),
        "size_human": format_size(len(data)),
        "width": width,
        "height": height,
        "mode": mode,
        "can_convert": can_be_source,
        "targets": targets,
    })


# کش موقتِ درون‌حافظه‌ای برای نگه‌داشتن بایت‌های فایل بین درخواست detect و convert
# (برای سادگی دمو؛ در محیط تولید باید با Redis/فایل موقت جایگزین شود)
_CACHE: dict[str, bytes] = {}
_CACHE_NAMES: dict[str, str] = {}


@app.route("/api/convert", methods=["POST"])
def api_convert():
    target = request.form.get("target", "").upper()
    token = request.form.get("token", "")

    if target not in FORMATS:
        return jsonify(error="فرمت مقصد نامعتبر است."), 400
    if target not in CONVERTIBLE_TARGETS:
        return jsonify(error=f"در حال حاضر تبدیل به {FORMATS[target]['label']} پشتیبانی نمی‌شود."), 400

    data = None
    filename = "image"
    if token and token in _CACHE:
        data = _CACHE[token]
        filename = _CACHE_NAMES.get(token, "image")
    elif "file" in request.files:
        f = request.files["file"]
        data = f.read()
        filename = f.filename or "image"
    else:
        return jsonify(error="فایل ورودی پیدا نشد. دوباره آپلود کنید."), 400

    src_key, _ = detect_format(data, filename)
    if not src_key:
        return jsonify(error="فرمت فایل ورودی شناسایی نشد."), 422
    if src_key not in CONVERTIBLE_SOURCES:
        return jsonify(error=f"تبدیل از {FORMATS[src_key]['label']} در حال حاضر پشتیبانی نمی‌شود."), 400

    try:
        with Image.open(io.BytesIO(data)) as img:
            img = ImageOps.exif_transpose(img)  # چرخش صحیح بر اساس متادیتای دوربین
            save_kwargs = {}
            out_format = FORMATS[target]["save_as"]

            # فرمت‌هایی که آلفا/شفافیت پشتیبانی نمی‌کنند نیاز به پس‌زمینه‌ی سفید دارند
            no_alpha = {"JPEG", "BMP", "PDF"}
            if out_format in no_alpha and img.mode in ("RGBA", "LA", "P"):
                bg = Image.new("RGB", img.size, (255, 255, 255))
                rgba = img.convert("RGBA")
                bg.paste(rgba, mask=rgba.split()[-1])
                img = bg
            elif img.mode == "P" and out_format not in ("GIF", "ICO"):
                img = img.convert("RGBA") if "transparency" in img.info else img.convert("RGB")

            if out_format == "JPEG":
                save_kwargs["quality"] = 92
                save_kwargs["optimize"] = True
                if img.mode != "RGB":
                    img = img.convert("RGB")
            elif out_format == "WEBP":
                save_kwargs["quality"] = 90
            elif out_format == "ICO":
                w, h = img.size
                side = min(256, max(16, min(w, h)))
                save_kwargs["sizes"] = [(side, side)]
            elif out_format == "ICNS":
                # ICNS نیازمند حداقل تصویر ۱۶×۱۶ و ترجیحاً مربعی است
                side = min(img.size)
                img = img.crop((0, 0, side, side)) if img.size[0] != img.size[1] else img
                img = img.resize((1024, 1024)) if max(img.size) < 16 else img
                if img.mode != "RGBA":
                    img = img.convert("RGBA")
            elif out_format == "PDF" and img.mode not in ("RGB", "L"):
                img = img.convert("RGB")

            buf = io.BytesIO()
            img.save(buf, format=out_format, **save_kwargs)
            buf.seek(0)
    except Exception as e:
        return jsonify(error=f"تبدیل با خطا مواجه شد: {e}"), 500

    STATS["conversions"] += 1
    STATS["convert_by_target"][target] = STATS["convert_by_target"].get(target, 0) + 1
    log_activity("تبدیل", f"{src_key} → {target} ({filename})")

    out_ext = FORMATS[target]["exts"][0]
    base = os.path.splitext(os.path.basename(filename))[0] or "image"
    download_name = f"{base}{out_ext}"

    return send_file(
        buf,
        mimetype=FORMATS[target]["mime"],
        as_attachment=True,
        download_name=download_name,
    )


@app.route("/api/health")
def health():
    return jsonify(status="ok", site=SITE_NAME, heif=HEIF_AVAILABLE, avif=AVIF_AVAILABLE)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
