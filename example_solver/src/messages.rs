pub struct Message<T> {
    pub code: u64,
    pub msg: T,
}

pub struct Auth {
    pub solver_id: String,
    pub solver_addresses: Vec<String>,
}

pub struct AuthSigned {
    pub solver_id: String,
    pub solver_addresses: Vec<String>,
    pub signature: String,
    pub hash: String,
}
