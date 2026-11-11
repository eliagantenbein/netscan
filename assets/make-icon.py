"""Draws the NetScan icon (radar on a blue tile) without extra packages.

Writes assets/icon.png (256 px, window icon), assets/icon.ico (16-256 px, Windows exe)
and assets/icon-mac.png (1024 px with Apple's margin, turned into .icns by mac/build-app.sh).
Run: python assets/make-icon.py
"""
import math
import struct
import zlib
from pathlib import Path

HERE = Path(__file__).parent
TOP, BOTTOM = (37, 99, 235), (8, 145, 178)  # blue-600 -> cyan-600
WHITE, GREEN = (255, 255, 255), (74, 222, 128)


def render(size, margin):
    """RGBA bytes; geometry in units of the tile (0..1), coverage from signed distances."""
    px = 1.0 / size
    tile = 1.0 - 2 * margin
    radius = 0.225 * tile
    cx = cy = 0.5
    rings = (0.30 * tile, 0.18 * tile)
    stroke = max(0.028 * tile, 1.2 * px)
    sweep_from, sweep_to = math.radians(-100), math.radians(-10)  # wedge up to the right, screen y points down
    blips = [(rings[0], math.radians(-35), WHITE), (rings[1], math.radians(150), WHITE), (rings[0], math.radians(65), GREEN)]
    out = bytearray()
    for j in range(size):
        y = (j + 0.5) * px
        for i in range(size):
            x = (i + 0.5) * px
            # rounded tile
            qx = max(abs(x - 0.5) - (tile / 2 - radius), 0.0)
            qy = max(abs(y - 0.5) - (tile / 2 - radius), 0.0)
            d = math.hypot(qx, qy) - radius
            a_tile = min(max(0.5 - d / px, 0.0), 1.0)
            if a_tile == 0.0:
                out += b"\0\0\0\0"
                continue
            t = min(max((x + y) / 2, 0.0), 1.0)
            col = [TOP[k] + (BOTTOM[k] - TOP[k]) * t for k in range(3)]

            def over(c, a):
                for k in range(3):
                    col[k] += (c[k] - col[k]) * a

            dx, dy = x - cx, y - cy
            r = math.hypot(dx, dy)
            ang = math.atan2(dy, dx)
            # sweep: fades in toward its leading edge
            if r < rings[0] and sweep_from <= ang <= sweep_to:
                f = (ang - sweep_from) / (sweep_to - sweep_from)
                edge = min(max(0.5 - (r - rings[0]) / px, 0.0), 1.0)
                over(WHITE, 0.38 * f * f * edge)
            for ring in rings:
                over(WHITE, 0.9 * min(max(0.5 - (abs(r - ring) - stroke / 2) / px, 0.0), 1.0))
            # leading edge line of the sweep
            ex, ey = math.cos(sweep_to), math.sin(sweep_to)
            along = dx * ex + dy * ey
            if 0 <= along <= rings[0]:
                dist = abs(dx * ey - dy * ex)
                over(WHITE, min(max(0.5 - (dist - stroke / 2) / px, 0.0), 1.0))
            over(WHITE, min(max(0.5 - (r - 0.05 * tile) / px, 0.0), 1.0))
            for br, ba, bc in blips:
                bx, by = cx + br * math.cos(ba), cy + br * math.sin(ba)
                over(bc, min(max(0.5 - (math.hypot(x - bx, y - by) - 0.052 * tile) / px, 0.0), 1.0))
            out += bytes(int(round(c)) for c in col) + bytes([int(round(255 * a_tile))])
    return bytes(out)


def png(size, rgba):
    rows = b"".join(b"\0" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def dib(size, rgba):
    """Classic ICO bitmap: BGRA rows bottom-up plus an all-zero AND mask; older Windows APIs can't read PNG entries."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = b"".join(
        bytes(rgba[(y * size + x) * 4 + c] for x in range(size) for c in (2, 1, 0, 3)) for y in reversed(range(size))
    )
    mask = b"\0" * (((size + 31) // 32) * 4 * size)
    return header + pixels + mask


def ico(images):
    """ICO entries: bitmaps for the small sizes, PNG for 256 px."""
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset + len(blobs))
        blobs += data
    return head + entries + blobs


if __name__ == "__main__":
    full = 0.03  # Windows icons fill their square
    (HERE / "icon.png").write_bytes(png(256, render(256, full)))
    sizes = (16, 24, 32, 48, 64, 128, 256)
    (HERE / "icon.ico").write_bytes(ico([(s, (png if s == 256 else dib)(s, render(s, full))) for s in sizes]))
    (HERE / "icon-mac.png").write_bytes(png(1024, render(1024, 100 / 1024)))  # Apple grid: 824 px tile
    print("assets/icon.png, assets/icon.ico, assets/icon-mac.png geschrieben")
