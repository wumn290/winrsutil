pub(crate) struct Defer<F: Fn()>(pub(crate) F);

impl<F: Fn()> Drop for Defer<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}
