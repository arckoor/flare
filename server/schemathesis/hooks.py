from pathlib import Path
import schemathesis
from hypothesis import strategies as st

image_dir = Path("../flare-test/images")
png_images = []
jpeg_images = []

for path in image_dir.glob("*"):
    with open(path, "rb") as f:
        data = f.read()
    if path.suffix.lower() == ".png":
        png_images.append(data)
    elif path.suffix.lower() in (".jpg", ".jpeg"):
        jpeg_images.append(data)

png_strategy = st.sampled_from(png_images)
jpeg_strategy = st.sampled_from(jpeg_images)
schemathesis.openapi.media_type("image/png", png_strategy)
schemathesis.openapi.media_type("image/jpeg", jpeg_strategy)
