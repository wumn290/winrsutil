pub(crate) use std::error::Error as StdError;
use std::fmt;
pub(crate) use std::result::Result as StdResult;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WinRsUtilError {
    code: usize,
    category: String,
    message: String,
}

pub(crate) type WRUE = WinRsUtilError;

impl WinRsUtilError {
    pub(crate) fn new(code: usize, category: String, message: String) -> Self {
        Self {
            code,
            category,
            message,
        }
    }

    pub(crate) const fn code(&self) -> usize {
        self.code
    }

    pub(crate) const fn category(&self) -> &String {
        &self.category
    }

    pub(crate) const fn message(&self) -> &String {
        &self.message
    }
}

impl fmt::Display for WinRsUtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "winrsutil error: {}, code: {}, message: {}",
            self.category(), self.code(), self.message()
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

    #[test]
    fn it_works() {}
}
