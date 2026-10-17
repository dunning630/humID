# Specimen payment-card camera fixtures for tests/browser/cards.mjs (test number, not a real card).
import sys
from PIL import Image, ImageDraw, ImageFont
out = sys.argv[1]
W, H = 1080, 1920
CW, CH = 820, 517
mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
sans = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
sansb = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
def frame(draw_card):
    im = Image.new("RGB", (W, H), (51, 47, 42))
    card = Image.new("RGB", (CW, CH), (232, 236, 241))
    d = ImageDraw.Draw(card)
    draw_card(d)
    mask = Image.new("L", (CW, CH), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, CW - 1, CH - 1], 26, fill=255)
    im.paste(card, ((W - CW) // 2, (H - CH) // 2), mask)
    return im
def front(d):
    d.text((40, 30), "SPECIMEN BANK", font=ImageFont.truetype(sansb, 34), fill=(30, 40, 60))
    d.text((40, 76), "TEST CARD - NOT A REAL CARD", font=ImageFont.truetype(sans, 18), fill=(90, 100, 110))
    d.rounded_rectangle([40, 140, 130, 205], 10, fill=(196, 170, 100))
    d.text((40, 262), "4111 1111 1111 1111", font=ImageFont.truetype(mono, 58), fill=(20, 25, 35))
    d.text((300, 348), "VALID THRU", font=ImageFont.truetype(sans, 16), fill=(60, 70, 80))
    d.text((420, 336), "08/29", font=ImageFont.truetype(mono, 40), fill=(20, 25, 35))
    d.text((40, 420), "JANE SPECIMEN", font=ImageFont.truetype(mono, 40), fill=(20, 25, 35))
    d.text((640, 420), "VISA", font=ImageFont.truetype(sansb, 52), fill=(26, 31, 113))
def back(d):
    d.rectangle([0, 50, CW, 140], fill=(25, 25, 25))
    d.rectangle([40, 190, 560, 260], fill=(250, 250, 245))
    d.text((60, 205), "1111  123", font=ImageFont.truetype(mono, 40), fill=(20, 20, 20))
    d.text((40, 300), "Call 1-800-555-0123 for customer service", font=ImageFont.truetype(sans, 26), fill=(40, 45, 55))
    d.text((40, 350), "SPECIMEN BANK - TEST CARD - NOT A REAL CARD", font=ImageFont.truetype(sans, 20), fill=(90, 100, 110))
for name, fn in (("camera-paycard-front", front), ("camera-paycard-back", back)):
    im = frame(fn)
    im.save(f"{out}/{name}.mjpeg", "JPEG", quality=90)
    im.resize((360, 640)).save(f"{out}/{name}-preview.png")
