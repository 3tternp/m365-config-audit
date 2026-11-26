"""Generate assets/icon.{png,ico}, icon_64.png (shield with check + four tiles (neutral colours, not a vendor logo)). Requires Pillow."""
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets"
OUT.mkdir(exist_ok=True)
S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((0, 0, S - 1, S - 1), radius=220, fill=(24, 32, 56, 255))
cx = S // 2
d.polygon([(cx, 130), (840, 250), (840, 540), (cx, 900), (184, 540), (184, 250)], fill=(245, 247, 252, 255))
# four Microsoft-style tiles inside the shield
for (x, y), col in zip([(330, 300), (520, 300), (330, 490), (520, 490)], [(37, 99, 235), (14, 165, 233), (99, 102, 241), (20, 184, 166)]):
    d.rectangle((x, y, x + 170, y + 170), fill=col)
d.ellipse((600, 590, 840, 830), fill=(34, 168, 99, 255))
d.line([(655, 715), (705, 765), (790, 660)], fill=(255, 255, 255, 255), width=34, joint="curve")
img.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
img.resize((64, 64), Image.LANCZOS).save(OUT / "icon_64.png")
img.save(OUT / "icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icons written to", OUT)
