"""Render the KAM mark to a PNG for Tauri's icon generator.

The mark is authored as SVG (kam-mark.svg), but `tauri icon` wants a large
raster source. Rather than add a rasteriser to the toolchain, the same geometry
is drawn here with Pillow at 4x and downsampled, which is also what gives it
antialiasing -- Pillow's arc and polygon drawing have none of their own.

The wordmark is deliberately left off. At 32 pixels, which is where an app icon
actually lives, "KAM" is three grey smudges.

    python assets/branding/render-icon.py
    cd ui && npx tauri icon ../assets/branding/kam-icon.png
"""

from pathlib import Path
from PIL import Image, ImageDraw

# Authored at 256; drawn at 1024 and supersampled 4x on top of that.
VIEWBOX = 256
OUT = 1024
SS = 4
S = OUT * SS / VIEWBOX

BACKGROUND = (10, 13, 20, 255)
BLUE = (74, 124, 255, 255)
FILL = (58, 99, 216, 255)


def scale(value):
    return value * S


def main():
    size = OUT * SS
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.ellipse([0, 0, size - 1, size - 1], fill=BACKGROUND)

    ring_radius = scale(108)
    centre = size / 2
    box = [
        centre - ring_radius,
        centre - ring_radius,
        centre + ring_radius,
        centre + ring_radius,
    ]
    ring_width = int(scale(7))

    # Pillow measures clockwise from 3 o'clock, so the top of the circle is 270
    # and the bottom is 90 -- the opposite of the SVG's convention.
    draw.arc(box, 170, 370, fill=BLUE, width=ring_width)
    draw.arc(box, 30, 150, fill=BLUE, width=ring_width)

    outer = [(scale(128), scale(45)), (scale(180), scale(135)), (scale(76), scale(135))]
    draw.line(outer + [outer[0]], fill=BLUE, width=int(scale(7)), joint="curve")

    inner = [(scale(102), scale(90)), (scale(154), scale(90)), (scale(128), scale(135))]
    draw.polygon(inner, fill=FILL)

    image = image.resize((OUT, OUT), Image.LANCZOS)
    destination = Path(__file__).parent / "kam-icon.png"
    image.save(destination)
    print(f"wrote {destination} ({OUT}x{OUT})")


if __name__ == "__main__":
    main()
