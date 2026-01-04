from PIL import Image

WIDTH = 4096
HEIGHT = 4
OUTPUT = "base.webp"

img = Image.new("RGB", (WIDTH, HEIGHT), (128, 128, 128))
img.save(
    OUTPUT,
    "WEBP",
    quality=90,
    method=3
)

print("[+] Base WebP generated:", OUTPUT)
