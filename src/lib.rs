mod structs;

pub use structs::*;


pub struct Checker {

}

impl Checker {
    pub fn new() -> Self {
        Self {

        }
    }

    pub fn check(&self) -> Option<bool> {
        // TODO make real implem
        Some(true)
    }
}