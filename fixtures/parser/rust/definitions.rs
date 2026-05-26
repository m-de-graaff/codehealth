use std::fmt::Debug;

pub fn add(left: i32, right: i32) -> i32 {
    left + right
}

pub fn identity<T>(value: T) -> T {
    value
}

pub async fn fetch_value() -> i32 {
    1
}

pub trait Loader {
    fn load(&self) -> String {
        String::new()
    }
}

pub struct Repository;

impl Repository {
    pub fn save(&self, value: String) -> String {
        value
    }
}

pub fn macro_heavy<T: Debug>(value: T) {
    println!("{value:?}");
}
