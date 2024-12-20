mod structs;

pub use structs::*;


pub struct Checker {

}

impl Checker {
    pub fn new() -> Self {
        Self {

        }
    }

    pub fn check(&self, data: Vec<u8>, signature: Vec<u8>) -> Option<bool> {
        // TODO make real implem
        Some(true)
    }
}