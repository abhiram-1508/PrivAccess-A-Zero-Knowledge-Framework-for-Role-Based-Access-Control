use std::collections::HashMap;
use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;
use serde::Serialize;

pub static ROLES: Lazy<HashMap<String, BigUint>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("ADMIN".to_string(), BigUint::from_str_radix("123456789012345678901234567890", 10).unwrap());
    m.insert("FACULTY".to_string(), BigUint::from_str_radix("98765432109876543210987654321", 10).unwrap());
    m.insert("STUDENT".to_string(), BigUint::from_str_radix("112233445566778899001122334455", 10).unwrap());
    m
});

pub const ADMIN_PASSWORD: &str = "Admin@1234";

#[derive(Debug, Serialize, Clone)]
pub struct Faculty {
    pub id: &'static str,
    pub pin: &'static str,
}

pub const FACULTIES: &[Faculty] = &[
    Faculty { id: "Fac1", pin: "1234" },
    Faculty { id: "Fac2", pin: "5678" },
    Faculty { id: "Fac3", pin: "9876" },
    Faculty { id: "Fac4", pin: "5432" },
];

pub const SECTIONS: &[&str] = &["A", "B", "C", "D", "E", "F", "G", "H"];

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn get_role_permissions(role_name: &str) -> Option<Vec<&'static str>> {
    ROLE_PERMISSIONS.get(role_name).cloned()
}
