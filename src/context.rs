use std::ffi::c_void;

pub(crate) trait Context {
    unsafe fn drop_at(ptr: *mut c_void)
    where
        Self: Sized,
    {
        drop(Box::from_raw(ptr as *mut Self));
    }
}

pub(crate) struct OwnedCtx {
    ptr: *mut c_void,
    dropper: unsafe fn(*mut c_void),
}

impl OwnedCtx {
    pub(crate) fn new<T: Context>(ctx: T) -> Self {
        let boxed = Box::new(ctx);
        let ptr = Box::into_raw(boxed) as *mut c_void;

        Self {
            ptr,
            dropper: T::drop_at,
        }
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for OwnedCtx {
    fn drop(&mut self) {
        unsafe {
            (self.dropper)(self.ptr);
        }
    }
}
