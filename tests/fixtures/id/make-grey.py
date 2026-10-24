# The first frame of each camera fixture as a grey PGM, for tools/docfind-golden.mjs.
#
#   python3 tests/fixtures/id/make-grey.py OUT_DIR
import io, os, sys
from PIL import Image

here = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for path in [os.path.join(here, "guide", n) for n in sorted(os.listdir(os.path.join(here, "guide")))] + [os.path.join(here, "camera-empty.mjpeg")]:
    if not path.endswith(".mjpeg"):
        continue
    b = open(path, "rb").read()
    i = b.find(b"\xff\xd8"); j = b.find(b"\xff\xd9", i)
    im = Image.open(io.BytesIO(b[i:j + 2])).convert("L")
    im.save(os.path.join(out, os.path.basename(path)[:-6] + ".pgm"))
