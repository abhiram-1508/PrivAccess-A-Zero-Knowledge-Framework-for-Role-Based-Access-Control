use std::collections::HashMap;
use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;

pub static ROLES: Lazy<HashMap<String, BigUint>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Using the same huge integers from Python code
    m.insert("ADMIN".to_string(), BigUint::from_str_radix("123456789012345678901234567890", 10).unwrap());
    m.insert("FACULTY".to_string(), BigUint::from_str_radix("98765432109876543210987654321", 10).unwrap());
    m.insert("STUDENT".to_string(), BigUint::from_str_radix("112233445566778899001122334455", 10).unwrap());
    m
});

pub static ROLE_PERMISSIONS: Lazy<HashMap<String, Vec<&'static str>>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("ADMIN".to_string(), vec!["read", "write", "delete"]);
    m.insert("FACULTY".to_string(), vec!["read", "write"]);
    m.insert("STUDENT".to_string(), vec!["read"]);
    m
});

pub fn get_role_secret(role_name: &str) -> Option<BigUint> {
    ROLES.get(role_name).cloned()
}

pub fn get_role_permissions(role_name: &str) -> Option<Vec<&'static str>> {
    ROLE_PERMISSIONS.get(role_name).cloned()
}
