# A cluttered-desk camera fixture for the barcode finder (tests/browser/idscan.mjs):
# the specimen license's back (card-back.jpg, test data, not a real license) lying
# sideways, small and off-centre in the lower right, slightly tilted, on a wood-grain
# desk beside a printed page and a store loyalty card whose own PDF417 barcode is
# bigger and nearer the middle (a decoy: it isn't a license barcode and must be passed
# over). Nothing is near the on-screen frame.
#   pip install pdf417gen pillow && python3 tests/fixtures/id/make-desk.py tests/fixtures/id
import random, sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import pdf417gen

out = sys.argv[1]
here = __file__.rsplit("/", 1)[0]
W, H = 1080, 1920
rnd = random.Random(7)
sans = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
sansb = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
serif = "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"

# the desk: warm wood grain
desk = Image.new("RGB", (W, H), (120, 84, 52))
d = ImageDraw.Draw(desk)
for y in range(0, H, 3):
    t = rnd.randint(-14, 14)
    d.line([(0, y), (W, y + rnd.randint(-6, 6))], fill=(120 + t, 84 + t, 52 + t // 2), width=3)
desk = desk.filter(ImageFilter.GaussianBlur(1.2))

def paste(img, deg, cx, cy):
    """Paste img turned deg degrees (counter-clockwise), centred at cx, cy, with a soft shadow."""
    r = img.convert("RGBA").rotate(deg, expand=True, resample=Image.BICUBIC)
    sh = Image.new("RGBA", r.size, (0, 0, 0, 0))
    sh.putalpha(r.split()[3].point(lambda a: a * 0.35))
    sh = sh.filter(ImageFilter.GaussianBlur(10))
    x, y = int(cx - r.width / 2), int(cy - r.height / 2)
    desk.paste(sh, (x + 10, y + 14), sh)
    desk.paste(r, (x, y), r)

# a printed page, top left, partly off the desk's edge
page = Image.new("RGB", (620, 800), (246, 244, 238))
pd = ImageDraw.Draw(page)
pd.text((40, 40), "Account statement", font=ImageFont.truetype(serif, 34), fill=(30, 30, 30))
words = "the balance due account payment date amount county notice your property total over will make".split()
for i in range(26):
    pd.text((40, 110 + i * 26), " ".join(rnd.choice(words) for _ in range(rnd.randint(6, 10))), font=ImageFont.truetype(serif, 18), fill=(40, 40, 40))
paste(page, -8, 250, 380)

# a store loyalty card with its own PDF417, near the middle: the decoy
loyalty = Image.new("RGB", (640, 404), (250, 250, 250))
ld = ImageDraw.Draw(loyalty)
ld.rectangle([0, 0, 640, 70], fill=(170, 30, 40))
ld.text((24, 16), "SPECIMEN MARKET  ·  REWARDS", font=ImageFont.truetype(sansb, 30), fill=(255, 255, 255))
codes = pdf417gen.encode("REWARDS MEMBER 00421337 SPECIMEN MARKET TEST CARD", columns=4, security_level=3)
bar = pdf417gen.render_image(codes, scale=4, ratio=4, padding=8).convert("RGB")
bar = bar.resize((580, min(230, int(580 * bar.height / bar.width))), Image.NEAREST)
loyalty.paste(bar, (30, 110))
ld.text((24, 360), "Not a license. Test card.", font=ImageFont.truetype(sans, 20), fill=(90, 90, 90))
paste(loyalty, 4, 470, 980)

# the license's back, sideways, small, lower right, tilted 3°
lic = Image.open(f"{here}/card-back.jpg").convert("RGB").resize((560, 353), Image.LANCZOS)
paste(lic, 93, 840, 1520)

# a camera's softness and noise
img = desk.filter(ImageFilter.GaussianBlur(0.6))
noise = Image.effect_noise((W, H), 10).convert("RGB")
img = Image.blend(img, noise, 0.04)
img.save(f"{out}/camera-license-desk.mjpeg", "JPEG", quality=90)
img.resize((360, 640)).save(f"{out}/camera-license-desk-preview.png")
