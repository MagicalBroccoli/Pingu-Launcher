//! Native C entry used to exercise ART initialization from ordinary Wine PE
//! context. It does not install another signal or syscall bridge.

/// The caller must be an ordinary Wine PE thread with an initialized TEB,
/// not a signal handler or a native worker. Returns one only after the real
/// private provider and dispatcher initialization succeeds, or negative errno
/// on failure so diagnostic callers retain the actual failure category.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pingu_artifact_prepare() -> libc::c_int {
    let _errno = crate::errno::Errno::save();
    // This is an ordinary Wine PE preparation boundary. The observer may have
    // seen Wine mappings before any CPUID query, so mark the Wine context here
    // before the resolver registration asks for the TEB dispatch guard.
    crate::artifact::mark_detected();
    if !crate::artifact::resolver::register_unwind_from_prepare() {
        return -libc::EOPNOTSUPP;
    }
    match crate::artifact::prepare() {
        Ok(()) => 1,
        Err(error) => {
            use crate::artifact::InitializeError;
            use crate::artifact::kuser::PrepareError;
            let code = match error {
                InitializeError::UnsupportedGsBaseAccess => libc::EOPNOTSUPP,
                InitializeError::NotWineThread => libc::EINVAL,
                InitializeError::Busy => libc::EBUSY,
                InitializeError::Dispatcher => libc::EIO,
                InitializeError::Provider(error) => match error {
                    PrepareError::System(code)
                    | PrepareError::Worker(code)
                    | PrepareError::Rollback(code) => code,
                    PrepareError::UnsupportedPageSize => libc::EOPNOTSUPP,
                    PrepareError::Busy => libc::EBUSY,
                    PrepareError::IncoherentClock => libc::EAGAIN,
                    PrepareError::WorkerTimeout => libc::ETIMEDOUT,
                    PrepareError::InvalidWineMapping | PrepareError::InvalidDispatchMapping => {
                        libc::EINVAL
                    }
                },
            };
            -code
        }
    }
}
