"""Generates the IAMClient4D app icon set (shield + padlock on the indigo-violet brand gradient).
Usage: python generate_icons.py   (needs Pillow). Output goes next to this script."""
import math, os, re
from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
C0, C1 = (0x43, 0x38, 0xCA), (0x7C, 0x3A, 0xED)   # same stops as the app header gradient
LOCK = (0x4F, 0x46, 0xE5)
SS = 4

SHIELD = "M50,5 C62,13 74,16 86,17 L86,48 C86,70 71,86 50,95 C29,86 14,70 14,48 L14,17 C26,16 38,13 50,5 Z"
# Padlock in the same 100x100 box: shackle ring, body, keyhole
SHACKLE = "M36,47 V40 A14,14 0 0 1 64,40 V47 H58 V40 A8,8 0 0 0 42,40 V47 Z"
BODY = "M33,47 H67 V73 Q67,76 64,76 H36 Q33,76 33,73 Z"
KEYHOLE = "M50,53 A4.5,4.5 0 1 1 50,62 A4.5,4.5 0 1 1 50,53 Z M48,60 H52 V68 H48 Z"


def bez(p0, p1, p2, p3, n=24):
    return [tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t * t * c + t ** 3 * d
                  for a, b, c, d in zip(p0, p1, p2, p3)) for t in (i / n for i in range(1, n + 1))]


def arc(cur, rx, ry, large, sweep, end, n=32):
    (x1, y1), (x2, y2) = cur, end
    dx, dy = (x1 - x2) / 2, (y1 - y2) / 2
    lam = (dx / rx) ** 2 + (dy / ry) ** 2
    if lam > 1:
        rx *= math.sqrt(lam)
        ry *= math.sqrt(lam)
    num = rx * rx * ry * ry - rx * rx * dy * dy - ry * ry * dx * dx
    co = math.sqrt(max(0, num / (rx * rx * dy * dy + ry * ry * dx * dx))) * (-1 if large == sweep else 1)
    cx, cy = co * rx * dy / ry + (x1 + x2) / 2, -co * ry * dx / rx + (y1 + y2) / 2
    a1 = math.atan2((y1 - cy) / ry, (x1 - cx) / rx)
    a2 = math.atan2((y2 - cy) / ry, (x2 - cx) / rx)
    d = a2 - a1
    if sweep and d < 0:
        d += 2 * math.pi
    if not sweep and d > 0:
        d -= 2 * math.pi
    return [(cx + rx * math.cos(a1 + d * i / n), cy + ry * math.sin(a1 + d * i / n)) for i in range(1, n + 1)]


def parse(d):
    """SVG path subset (M L H V C Q A Z) -> list of polygons."""
    t = re.findall(r"[A-Za-z]|-?\d+\.?\d*", d)
    polys, pts, cur, cmd = [], [], (0, 0), ""

    def f():
        return float(t.pop(0))

    while t:
        if t[0].isalpha():
            cmd = t.pop(0)
        if cmd == "M":
            if pts:
                polys.append(pts)
            cur = (f(), f())
            pts = [cur]
        elif cmd == "L":
            cur = (f(), f())
            pts.append(cur)
        elif cmd == "H":
            cur = (f(), cur[1])
            pts.append(cur)
        elif cmd == "V":
            cur = (cur[0], f())
            pts.append(cur)
        elif cmd == "C":
            p1, p2, p3 = (f(), f()), (f(), f()), (f(), f())
            pts += bez(cur, p1, p2, p3)
            cur = p3
        elif cmd == "Q":
            q, p3 = (f(), f()), (f(), f())
            c1 = (cur[0] + 2 / 3 * (q[0] - cur[0]), cur[1] + 2 / 3 * (q[1] - cur[1]))
            c2 = (p3[0] + 2 / 3 * (q[0] - p3[0]), p3[1] + 2 / 3 * (q[1] - p3[1]))
            pts += bez(cur, c1, c2, p3)
            cur = p3
        elif cmd == "A":
            rx, ry, _, la, sw = f(), f(), f(), int(f()), int(f())
            e = (f(), f())
            pts += arc(cur, rx, ry, la, sw, e)
            cur = e
        elif cmd == "Z":
            pass
    if pts:
        polys.append(pts)
    return polys


def gradient(size):
    n = 256   # diagonal ramp computed small, then upscaled (pure-Python per-pixel is too slow at 4096)
    ramp = Image.new("L", (n, n))
    ramp.putdata([round(255 * (x + y) / (2 * (n - 1))) for y in range(n) for x in range(n)])
    ramp = ramp.resize((size, size), Image.BILINEAR)
    return Image.composite(Image.new("RGB", (size, size), C1), Image.new("RGB", (size, size), C0), ramp)


def fill(draw, d, ox, oy, s, color):
    for p in parse(d):
        draw.polygon([(ox + x * s, oy + y * s) for x, y in p], fill=color)


def master(size=1024, scale=0.62, rounded=False):
    big = size * SS
    img = gradient(big).convert("RGBA")
    s = big * scale / 100
    ox = oy = (big - 100 * s) / 2
    sh = Image.new("RGBA", (big, big), (0, 0, 0, 0))   # soft shadow under the shield
    fill(ImageDraw.Draw(sh), SHIELD, ox, oy + big * 0.012, s, (20, 10, 80, 90))
    img = Image.alpha_composite(img, sh.filter(ImageFilter.GaussianBlur(big * 0.012)))
    dr = ImageDraw.Draw(img)
    fill(dr, SHIELD, ox, oy, s, (255, 255, 255, 255))
    for d in (SHACKLE, BODY):
        fill(dr, d, ox, oy, s, LOCK + (255,))
    fill(dr, KEYHOLE, ox, oy, s, (255, 255, 255, 255))
    if rounded:
        m = Image.new("L", (big, big), 0)
        ImageDraw.Draw(m).rounded_rectangle([0, 0, big - 1, big - 1], radius=big * 0.2237, fill=255)
        img.putalpha(m)
    return img.resize((size, size), Image.LANCZOS)


def save(img, rel, size, flat=False):
    p = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    out = img.resize((size, size), Image.LANCZOS)
    if flat:
        out = out.convert("RGB")
    out.save(p)


if __name__ == "__main__":
    sq, rd = master(1024), master(1024, rounded=True)
    save(sq, "IAMClient4D_icon_1024.png", 1024, flat=True)
    for n in (36, 48, 72, 96, 144, 192):
        save(rd, f"Android/LauncherIcon_{n}x{n}.png", n)
    for n in (1024, 180, 120, 152, 167, 80, 87, 58, 40, 60):
        save(sq, f"iOS/ApplicationIcon_{n}x{n}.png", n, flat=True)
    sq.resize((256, 256), Image.LANCZOS).save(
        os.path.join(HERE, "IAMClient4D.ico"),
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    for n in (24, 36, 48, 72, 96):   # notification icons: white shield with the lock cut out
        big = n * SS * 4
        im = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        dr = ImageDraw.Draw(im)
        s = big * 0.86 / 100
        o = (big - 100 * s) / 2
        fill(dr, SHIELD, o, o, s, (255, 255, 255, 255))
        for d in (SHACKLE, BODY):
            fill(dr, d, o, o, s, (0, 0, 0, 0))
        fill(dr, KEYHOLE, o, o, s, (255, 255, 255, 255))
        save(im, f"Android/NotificationIcon_{n}x{n}.png", n)

    # Splash images: the repository logo (images/IAMClient4D_logo.png) re-stacked, shield above and wordmark below
    logo = Image.open(os.path.join(HERE, "..", "..", "..", "..", "images", "IAMClient4D_logo.png")).convert("RGBA")
    shield = logo.crop((0, 0, 250, logo.height))
    shield = shield.crop(shield.getchannel("A").getbbox())
    word = logo.crop((250, 0, logo.width, logo.height))
    word = word.crop(word.getchannel("A").getbbox())

    def stacked(size, width):
        """Logo block of the given wordmark width centred on a transparent canvas."""
        w, h = size
        ww = width
        wh = round(ww * word.height / word.width)
        sw = round(ww * 0.78)                       # shield width relative to the wordmark
        sh = round(sw * shield.height / shield.width)
        gap = round(ww * 0.14)
        im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        top = (h - (sh + gap + wh)) // 2
        im.paste(shield.resize((sw, sh), Image.LANCZOS), ((w - sw) // 2, top), shield.resize((sw, sh), Image.LANCZOS))
        im.paste(word.resize((ww, wh), Image.LANCZOS), ((w - ww) // 2, top + sh + gap), word.resize((ww, wh), Image.LANCZOS))
        return im

    # Android 12+: the system masks the splash icon to a circle (2/3 of the canvas): fit the block inside it
    N = 864
    lo, hi = 100, N
    while hi - lo > 1:
        mid = (lo + hi) // 2
        blk = stacked((N, N), mid)
        ok = all(((x - N / 2) ** 2 + (y - N / 2) ** 2) <= (N / 3) ** 2
                 for x, y in ((blk.getchannel("A").getbbox()[i], blk.getchannel("A").getbbox()[j])
                              for i in (0, 2) for j in (1, 3)))
        lo, hi = (mid, hi) if ok else (lo, mid)
    stacked((N, N), lo).save(os.path.join(HERE, "Android/SplashLogo.png"))
    # Older Android: plain centred bitmap, 1 px = 1 dp
    for w, h in ((426, 320), (470, 320), (640, 480), (960, 720)):
        stacked((w, h), round(min(w, 480) * 0.62)).save(os.path.join(HERE, f"Android/SplashImage_{w}x{h}.png"))
