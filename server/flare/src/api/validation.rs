use std::io::BufReader;

use image::{GenericImageView, ImageReader};

use super::{
    api_params::{PaginatedSort, Paginator},
    error::RestError,
};

pub const MAX_TITLE_LEN: Option<usize> = Some(255);
pub const MAX_INFO_LEN: Option<usize> = None;
pub const MAX_NAME_LEN: Option<usize> = Some(60);

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

    if paginator
        .page
        .checked_mul(paginator.page_size)
        .is_none_or(|v| v > i64::MAX as u64)
    {
        return Err(RestError::bad_req(format!(
            "Page * Page size must be less than or equal to {}",
            i64::MAX
        )));
    }

    Ok(())
}

pub fn validate_text(text: &str, allow_empty: bool, limit: Option<usize>) -> Result<(), RestError> {
    if !allow_empty && text.is_empty() {
        return Err(RestError::bad_req("Text must not be empty".to_string()));
    }

    if let Some(limit) = limit
        && text.len() > limit
    {
        return Err(RestError::bad_req(format!(
            "Text must be less than or equal to {limit} characters"
        )));
    }

    if ammonia::is_html(text) {
        return Err(RestError::bad_req("Text must not contain HTML".to_string()));
    }

    Ok(())
}

pub fn inspect_validate_image(
    data: &axum::body::Bytes,
    format: &mime::Mime,
) -> Result<String, RestError> {
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
            .ok_or_else(|| RestError::bad_req("Invalid content type"))?,
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

#[cfg(test)]
mod tests {
    use crate::api::{
        api_params::{FetchPollSort, Paginator},
        validation::{inspect_validate_image, validate_paginator, validate_text},
    };

    #[test]
    fn test_validate_paginator() {
        let mut paginator = Paginator::<FetchPollSort> {
            page: 0,
            page_size: 2,
            asc: true,
            sort_by: None,
        };

        assert!(validate_paginator(&paginator, 2).is_ok());
        paginator.page_size = 3;
        assert!(validate_paginator(&paginator, 2).is_err());
        paginator.page_size = 0;
        assert!(validate_paginator(&paginator, 2).is_err());
    }

    #[test]
    fn test_validate_text() {
        assert!(validate_text("Hello world!", false, None).is_ok());
        assert!(validate_text("", true, None).is_ok());
        assert!(validate_text("", false, None).is_err());
        assert!(validate_text("0123456789", false, Some(10)).is_ok());
        assert!(validate_text("0123456789a", false, Some(10)).is_err());
        assert!(validate_text("<div>Hello, world!</div>", false, None).is_err());
        assert!(validate_text("<script>alert('xss')</script>", false, None).is_err());
    }

    #[test]
    fn test_validate_image() {
        let bytes: &[u8] = include_bytes!("../../../flare-test/images/1.png");
        let image = axum::body::Bytes::from(bytes);

        assert!(inspect_validate_image(&image, &mime::IMAGE_BMP).is_err());
        assert!(
            inspect_validate_image(&axum::body::Bytes::from("Hello, world!"), &mime::IMAGE_PNG)
                .is_err()
        );
        assert_eq!(
            inspect_validate_image(&image, &mime::IMAGE_PNG).unwrap(),
            "1/1".to_string()
        );

        let bytes: &[u8] = include_bytes!("../../../flare-test/images/3.png");
        let image = axum::body::Bytes::from(bytes);
        assert_eq!(
            inspect_validate_image(&image, &mime::IMAGE_PNG).unwrap(),
            "16/9".to_string()
        );
    }
}
