#[macro_export]
macro_rules! requires {
	($store:expr, $auth:expr $(, $($perm:expr),*)?) => {
		$store.jwt.validate($auth, vec![$($($perm),*)?]).await?
	};
}
