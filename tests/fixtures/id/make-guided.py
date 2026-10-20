# Camera fixtures for the guided scan (tests/browser/guided.mjs): a license back, a passport page
# and a payment card on a dark table, laid at known places relative to the on-screen outline, so
# the test can say what the guidance must answer and where the crop must land.
#
#   pip install pdf417gen pillow && python3 tests/fixtures/id/make-guided.py tests/fixtures/id/guide
#
# The outline's place in the video (1080 x 1920, the phone-sized test viewport 412 x 915, object-fit:
# cover) comes from the layout in styles/app.css (.dc-stage, .dc-frame): the browser test checks the
# app's own number (__humidGuide.rect) against GUIDE_ID1 / GUIDE_TD3 and says so if the layout moved.
# Each file is one JPEG (a still view) or several (a view that shakes). Test data only.
import math, os, random, sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageChops

out = sys.argv[1] if len(sys.argv) > 1 else "."
here = os.path.dirname(os.path.abspath(__file__))
W, H = 1080, 1920
GUIDE_ID1 = (141, 526, 797, 503)   # x, y, w, h in the video's pixels
GUIDE_TD3 = (141, 497, 797, 561)
GUIDE_PAGE = (141, 239, 797, 1076)  # 3.0.1: a paper page's outline (1:1.35, standing up)
sans = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
sansb = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

def table(seed=5):
    rnd = random.Random(seed)
    im = Image.new("RGB", (W, H), (58, 50, 44))
    d = ImageDraw.Draw(im)
    for y in range(0, H, 4):
        t = rnd.randint(-7, 7)
        d.line([(0, y), (W, y + rnd.randint(-3, 3))], fill=(58 + t, 50 + t, 44 + t // 2), width=4)
    return im.filter(ImageFilter.GaussianBlur(1.0))

def rounded(img, frac=0.035):
    m = Image.new("L", img.size, 0)
    ImageDraw.Draw(m).rounded_rectangle([0, 0, img.width - 1, img.height - 1], int(img.width * frac), fill=255)
    r = img.convert("RGBA")
    r.putalpha(m)
    return r

def paycard(side):
    CW, CH = 820, 517
    card = Image.new("RGB", (CW, CH), (232, 236, 241))
    d = ImageDraw.Draw(card)
    if side == "front":
        d.text((40, 30), "SPECIMEN BANK", font=ImageFont.truetype(sansb, 34), fill=(30, 40, 60))
        d.text((40, 76), "TEST CARD - NOT A REAL CARD", font=ImageFont.truetype(sans, 18), fill=(90, 100, 110))
        d.rounded_rectangle([40, 140, 130, 205], 10, fill=(196, 170, 100))
        d.text((40, 262), "4111 1111 1111 1111", font=ImageFont.truetype(mono, 58), fill=(20, 25, 35))
        d.text((300, 348), "VALID THRU", font=ImageFont.truetype(sans, 16), fill=(60, 70, 80))
        d.text((420, 336), "08/29", font=ImageFont.truetype(mono, 40), fill=(20, 25, 35))
        d.text((40, 420), "JANE SPECIMEN", font=ImageFont.truetype(mono, 40), fill=(20, 25, 35))
        d.text((640, 420), "VISA", font=ImageFont.truetype(sansb, 52), fill=(26, 31, 113))
    else:
        d.rectangle([0, 50, CW, 140], fill=(25, 25, 25))
        d.rectangle([40, 190, 560, 260], fill=(250, 250, 245))
        d.text((60, 205), "1111  123", font=ImageFont.truetype(mono, 40), fill=(20, 20, 20))
        d.text((40, 300), "Call 1-800-555-0123 for customer service", font=ImageFont.truetype(sans, 26), fill=(40, 45, 55))
        d.text((40, 350), "SPECIMEN BANK - TEST CARD - NOT A REAL CARD", font=ImageFont.truetype(sans, 20), fill=(90, 100, 110))
    return card

def visa_page():
    """A passport page that is not the photo page: stamps and ruled lines, no machine-readable lines."""
    im = Image.open(f"{here}/passport-page.jpg").convert("RGB").resize((1000, 704))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, 1000, 704], fill=(236, 232, 214))
    rnd = random.Random(3)
    for i in range(7):
        x, y = 60 + (i % 3) * 300, 70 + (i // 3) * 210
        d.ellipse([x, y, x + 200, y + 150], outline=(60, 80, 140), width=5)
        d.text((x + 38, y + 56), "ENTRY", font=ImageFont.truetype(sansb, 34), fill=(60, 80, 140))
    for i in range(9):
        d.line([(60, 40 + i * 70), (940, 40 + i * 70)], fill=(200, 196, 180), width=2)
    return im

def place(card, guide, scale, dx=0.0, dy=0.0, deg=0.0, keystone=0.0, bg=None, round_=0.035):
    """The card, `scale` x the outline's width, centred (dx, dy) outline-sizes off its centre, turned deg clockwise."""
    gx, gy, gw, gh = guide
    cw = int(gw * scale)
    ch = int(cw * card.height / card.width)
    c = card.convert("RGB").resize((cw, ch), Image.LANCZOS)
    c = rounded(c, round_) if round_ else c.convert("RGBA")
    if keystone:
        # top narrower by `keystone` of the width (a phone held at an angle)
        k = keystone * cw / 2
        coeffs = _persp([(0, 0), (cw, 0), (cw, ch), (0, ch)], [(k, 0), (cw - k, 0), (cw, ch), (0, ch)])
        c = c.transform((cw, ch), Image.PERSPECTIVE, coeffs, Image.BICUBIC)
    if deg:
        c = c.rotate(-deg, expand=True, resample=Image.BICUBIC)
    base = bg.copy().convert("RGBA")
    sh = Image.new("RGBA", c.size, (0, 0, 0, 0))
    sh.putalpha(c.split()[3].point(lambda a: int(a * 0.4)))
    sh = sh.filter(ImageFilter.GaussianBlur(8))
    cx, cy = gx + gw / 2 + dx * gw, gy + gh / 2 + dy * gh
    x, y = int(cx - c.width / 2), int(cy - c.height / 2)
    base.alpha_composite(sh, (x + 6, y + 9))
    base.alpha_composite(c, (x, y))
    return base.convert("RGB")

def _persp(src, dst):
    # coefficients mapping output (dst) points to input (src) points for Image.transform
    import numpy as np
    A, B = [], []
    for (x, y), (u, v) in zip(dst, src):
        A.append([x, y, 1, 0, 0, 0, -u * x, -u * y]); B.append(u)
        A.append([0, 0, 0, x, y, 1, -v * x, -v * y]); B.append(v)
    return list(np.linalg.solve(np.array(A, float), np.array(B, float)))

def camera(img, seed=1, blur=0.0, glare=None, dark=1.0, noise=3.0):
    """The camera's softness and noise; optional blur (px), glare (cx, cy, radius px) and dimming."""
    if blur:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    if glare:
        gx, gy, r = glare
        g = Image.new("L", img.size, 0)
        gd = ImageDraw.Draw(g)
        gd.ellipse([gx - r, gy - r * 0.75, gx + r, gy + r * 0.75], fill=255)
        g = g.filter(ImageFilter.GaussianBlur(r * 0.22))
        g = g.point(lambda a: min(255, int(a * 2.2)))
        img = Image.composite(Image.new("RGB", img.size, (255, 255, 255)), img, g)
    if dark != 1.0:
        img = img.point(lambda v: int(v * dark))
    rnd = Image.effect_noise(img.size, noise).convert("RGB")
    return Image.blend(img, rnd, 0.03)

def save(name, frames):
    path = f"{out}/{name}.mjpeg"
    with open(path, "wb") as f:
        for im in frames:
            import io
            b = io.BytesIO()
            im.save(b, "JPEG", quality=82)
            f.write(b.getvalue())
    return path

def shaky(card, guide, n=6, amp=22, **kw):
    rnd = random.Random(11)
    bg = table()
    return [camera(place(card, guide, 0.97, dx=rnd.uniform(-amp, amp) / guide[2], dy=rnd.uniform(-amp, amp) / guide[3], deg=rnd.uniform(-1.5, 1.5), bg=bg), seed=i) for i in range(n)]

bg = table()
back = Image.open(f"{here}/card-back.jpg").convert("RGB")
front = Image.open(f"{here}/card-front.jpg").convert("RGB")
pp = Image.open(f"{here}/passport-page.jpg").convert("RGB")
import gzip
def pgm_gz(path):
    raw = gzip.open(path).read()
    parts = raw.split(b"\n", 3) if raw[:2] == b"P5" else None
    w, h = map(int, parts[1].split()) if len(parts[1].split()) == 2 else (None, None)
    return Image.frombytes("L", (w, h), parts[3][: w * h]).convert("RGB")
letter = pgm_gz(f"{here}/../docs/page-letter.pgm.gz").point(lambda v: int(v * 0.88))  # paper in a room's light, not clipped white
G1, G2, G3 = GUIDE_ID1, GUIDE_TD3, GUIDE_PAGE
gcx1, gcy1 = G1[0] + G1[2] / 2, G1[1] + G1[3] / 2
gcx2, gcy2 = G2[0] + G2[2] / 2, G2[1] + G2[3] / 2

# a license's back (the barcode): right size, small, big and cut off, tilted, a little tilted, blurred, glared, dark, shaking, at an angle, and the front instead
specs = {
    "lic-back-ok":       dict(card=back, g=G1, scale=0.97),
    "lic-back-small":    dict(card=back, g=G1, scale=0.58),
    "lic-back-big":      dict(card=back, g=G1, scale=1.5),
    "lic-back-tilt":     dict(card=back, g=G1, scale=0.93, deg=10),
    "lic-back-tilt3":    dict(card=back, g=G1, scale=0.95, deg=3.5),
    "lic-back-blur":     dict(card=back, g=G1, scale=0.97, blur=6),
    "lic-back-glare":    dict(card=back, g=G1, scale=0.97, glare=(gcx1 - 210, gcy1 + 20, 120)),
    "lic-back-dark":     dict(card=back, g=G1, scale=0.97, dark=0.16),
    "lic-back-keystone": dict(card=back, g=G1, scale=0.97, keystone=0.18),
    "lic-front-ok":      dict(card=front, g=G1, scale=0.97),
    "pp-ok":             dict(card=pp, g=G2, scale=0.97, round_=0),
    "pp-small":          dict(card=pp, g=G2, scale=0.6, round_=0),
    "pp-big":            dict(card=pp, g=G2, scale=1.4, round_=0),
    "pp-tilt":           dict(card=pp, g=G2, scale=0.93, deg=9, round_=0),
    "pp-blur":           dict(card=pp, g=G2, scale=0.97, blur=6, round_=0),
    "pp-glare":          dict(card=pp, g=G2, scale=0.97, glare=(gcx2 - 150, gcy2 - 30, 130), round_=0),
    "pp-dark":           dict(card=pp, g=G2, scale=0.97, dark=0.16, round_=0),
    "pp-wrongpage":      dict(card=visa_page(), g=G2, scale=0.97, round_=0),
    "pay-front-ok":      dict(card=paycard("front"), g=G1, scale=0.97),
    "pay-front-small":   dict(card=paycard("front"), g=G1, scale=0.6),
    "pay-back-ok":       dict(card=paycard("back"), g=G1, scale=0.97),
    "page-letter-ok":    dict(card=letter, g=G3, scale=0.96, round_=0),
}
# ONLY=name1,name2 writes just those (the others keep their bytes)
only = set(filter(None, os.environ.get("ONLY", "").split(",")))
if only: specs = {k: v for k, v in specs.items() if k in only}
for name, s in specs.items():
    kw = dict(s)
    card, g = kw.pop("card"), kw.pop("g")
    cam = {k: kw.pop(k) for k in ("blur", "glare", "dark") if k in kw}
    save(name, [camera(place(card, g, bg=bg, **kw), **cam)])
if not only or "lic-back-shaky" in only: save("lic-back-shaky", shaky(back, G1, n=16))  # many different views: a few repeated ones let a sampler see two equal frames in a row, which a real shake never does
print("wrote", len(specs) + (0 if only and "lic-back-shaky" not in only else 1), "fixtures to", out)
