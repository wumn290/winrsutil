pub use std::error::Error as StdError;
use std::fmt;
pub use std::result::Result as StdResult;

#[derive(Clone, PartialEq, Eq)]
pub struct WinRsUtilError {
    code: usize,
    category: String,
    message: String,
}

pub type WRUE = WinRsUtilError;

impl WinRsUtilError {
    pub fn new(code: usize, category: String, message: String) -> Self {
        Self {
            code,
            category,
            message,
        }
    }

    pub const fn code(&self) -> usize {
        self.code
    }

    pub const fn category(&self) -> &String {
        &self.category
    }

    pub const fn message(&self) -> &String {
        &self.message
    }
}

impl fmt::Display for WinRsUtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "winrsutil error: {}, code: {}, message: {}",
            self.category, self.code, self.message
        )
    }
}

impl fmt::Debug for WinRsUtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "WinRsUtilError {{ category: {}, code: {}, message: {} }}",
            self.category, self.code, self.message
        )
    }
}

impl std::error::Error for WinRsUtilError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
