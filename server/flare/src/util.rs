use image::{GenericImageView, ImageReader};

use crate::api::error::RestError;

pub fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

pub fn calculate_aspect_ratio(
    data: &axum::body::Bytes,
    format: mime::Mime,
) -> Result<String, RestError> {
    let mut reader = ImageReader::new(std::io::Cursor::new(data.to_vec()));
    reader.set_format(
        image::ImageFormat::from_mime_type(format)
            .ok_or(RestError::bad_req("Invalid content type"))?,
    );
    let image = reader
        .decode()
        .map_err(|_| RestError::bad_req("Failed to read image"))?;

    let dimensions = image.dimensions();
    let divisor = gcd(dimensions.0, dimensions.1);

    Ok(format!(
        "{}/{}",
        dimensions.0 / divisor,
        dimensions.1 / divisor
    ))
}
