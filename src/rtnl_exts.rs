use nix::errno::Errno;

pub trait ErrorExt {
    fn is_errno(&self, errno: Errno) -> bool;
}

impl ErrorExt for rtnetlink::Error {
    fn is_errno(&self, errno: Errno) -> bool {
        match self {
            rtnetlink::Error::NetlinkError(err) => {
                err.to_io().raw_os_error() == Some(errno as i32)
            }
            _ => false,
        }
    }
}
