# Phone-sized camera fixtures for the capture benchmark (tests/bench/capture.mjs).
# The checked-in fake cameras are 1080x1920; a phone's camera hands the page 2160x3840 or
# more (getUserMedia asks for 3840x2160), and that is where capture time goes. This
# upscales each one 2x (bicubic, then a little sensor-like noise so the JPEG isn't
# unrealistically easy to compress) into a one-frame MJPEG the browser's fake camera loops.
#   python3 tests/bench/make-4k-fixtures.py OUTDIR
import io, os, random, sys
from PIL import Image, ImageFilter

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
here = os.path.dirname(os.path.abspath(__file__))
fx = os.path.join(here, "..", "fixtures")
SRC = {
    "license-back": "id/camera-card-back.mjpeg",
    "passport": "id/camera-passport.mjpeg",
    "paycard-front": "id/camera-paycard-front.mjpeg",
    "letter": "docs/camera-letter-tilted.mjpeg",
}
rnd = random.Random(3)
for name, rel in SRC.items():
    d = open(os.path.join(fx, rel), "rb").read()
    i = d.find(b"\xff\xd8"); j = d.rfind(b"\xff\xd9")
    im = Image.open(io.BytesIO(d[i:j + 2])).convert("RGB")
    im = im.resize((im.width * 2, im.height * 2), Image.BICUBIC).filter(ImageFilter.UnsharpMask(1.2, 60, 2))
    try:
        import numpy as np
        a = np.asarray(im).astype("int16")
        a += np.random.default_rng(5).normal(0, 3.5, a.shape[:2])[..., None].astype("int16")
        im = Image.fromarray(a.clip(0, 255).astype("uint8"))
    except ImportError:
        pass
    b = io.BytesIO(); im.save(b, "JPEG", quality=90)
    open(os.path.join(out, f"camera-{name}-4k.mjpeg"), "wb").write(b.getvalue())
    print(name, im.size, len(b.getvalue()))

# Flat pages as the phone's document scanner (ML Kit) hands them back: a JPEG whose long
# side is at most 3200 px (docscan.js maxSide).
from PIL import ImageDraw, ImageFont
import numpy as np
sans = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
serif = "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"

def noisy(im, s=3.0):
    a = np.asarray(im.convert("RGB")).astype("int16")
    a += np.random.default_rng(9).normal(0, s, a.shape[:2])[..., None].astype("int16")
    return Image.fromarray(a.clip(0, 255).astype("uint8"))

W, H = 2472, 3200  # a letter page
page = Image.new("RGB", (W, H), (244, 242, 236))
d = ImageDraw.Draw(page)
f1, f2 = ImageFont.truetype(serif, 54), ImageFont.truetype(sans, 40)
d.text((220, 200), "Statement of account", fill=(20, 20, 20), font=ImageFont.truetype(sans, 96))
y = 380
for n in range(52):
    d.text((220, y), f"{n + 1:02d}  Line item {n * 7 % 31} of the quarterly summary, carried forward    {1000 + n * 37:,}.00", fill=(30, 30, 30), font=f2 if n % 5 else f1)
    y += 54
    if y > H - 220: break
sh = np.linspace(1.0, 0.82, H)[:, None, None]  # a soft shadow down the page
page = Image.fromarray((np.asarray(page) * sh).astype("uint8"))
b = io.BytesIO(); noisy(page).save(b, "JPEG", quality=90)
open(os.path.join(out, "scanner-page-3200.jpg"), "wb").write(b.getvalue()); print("scanner-page", page.size, len(b.getvalue()))

pp = Image.open(os.path.join(fx, "id/passport-page.jpg")).convert("RGB")
k = 3200 / pp.width
pp = pp.resize((3200, round(pp.height * k)), Image.BICUBIC).filter(ImageFilter.UnsharpMask(1.5, 80, 2))
b = io.BytesIO(); noisy(pp, 2.0).save(b, "JPEG", quality=90)
open(os.path.join(out, "scanner-passport-3200.jpg"), "wb").write(b.getvalue()); print("scanner-passport", pp.size, len(b.getvalue()))
