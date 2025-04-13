use std::io::BufReader;

use image::{GenericImageView, ImageReader};

use super::{
    api_params::{PaginatedSort, Paginator},
    error::RestError,
};

type AspectRatio = String;

pub fn validate_paginator<S: PaginatedSort>(
    paginator: &Paginator<S>,
    max_limit: u64,
) -> Result<(), RestError> {
    if paginator.page_size == 0 {
        return Err(RestError::bad_req(
            "Page size must be greater than 0".to_string(),
        ));
    }

    if paginator.page_size > max_limit {
        return Err(RestError::bad_req(format!(
            "Page size must be less than or equal to {max_limit}"
        )));
    }

    Ok(())
}

// todo if we switch to VARCHAR, add Option<u32> max_length or something
pub fn validate_user_text(texts: Vec<&str>) -> Result<(), RestError> {
    for text in texts {
        if text.is_empty() {
            return Err(RestError::bad_req("Text must not be empty".to_string()));
        }

        if ammonia::is_html(text) {
            return Err(RestError::bad_req("Text must not contain HTML".to_string()));
        }
    }

    Ok(())
}

pub fn inspect_validate_image(
    data: &axum::body::Bytes,
    format: &mime::Mime,
) -> Result<AspectRatio, RestError> {
    fn gcd(mut a: u32, mut b: u32) -> u32 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    let image = ImageReader::with_format(
        BufReader::new(std::io::Cursor::new(data)),
        image::ImageFormat::from_mime_type(format)
            .ok_or(RestError::bad_req("Invalid content type"))?,
    )
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
