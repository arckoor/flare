#[macro_export]
macro_rules! requires {
    ($store:expr, $auth:expr $(, $($perm:expr),*)?) => {
        $store.jwt.validate($auth, &[$($($perm),*)?]).await
    };
}

#[macro_export]
macro_rules! transaction {
    ($sea:expr, $txn:ident, $body:block) => {
        $sea.transaction(|$txn| {
            Box::pin(async move $body)
        }).await.map_err(|e| RestError::from(e))
    };
}
