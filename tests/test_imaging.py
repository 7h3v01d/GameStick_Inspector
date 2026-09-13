import hashlib

from gamestick.imaging import sha256_file


def test_image_hash(tmp_path):
    data = b"gamestick-image-test" * 1000
    image = tmp_path / "card.img"
    image.write_bytes(data)
    assert sha256_file(image) == hashlib.sha256(data).hexdigest()
