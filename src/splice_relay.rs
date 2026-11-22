use std::io;
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::Interest;
use tokio::net::TcpStream;

const SPLICE_CHUNK: usize = 65536;

struct NonBlockingPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl NonBlockingPipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Maximize pipe buffer up to 256 KiB if kernel permits (ignored if unprivileged)
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 262144);
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }
}

impl Drop for NonBlockingPipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

pub fn tune_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let fd = stream.as_raw_fd();
    unsafe {
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn raw_splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

async fn splice_one_way(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
    let pipe = NonBlockingPipe::new()?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();

    let mut in_pipe: usize = 0;
    let mut eof = false;
    let mut total: u64 = 0;

    loop {
        if in_pipe > 0 {
            let wrote = dst
                .try_io(Interest::WRITABLE, || raw_splice(pipe.read_fd, dst_fd, in_pipe));
            match wrote {
                Ok(0) => return Ok(total),
                Ok(n) => {
                    in_pipe -= n;
                    total += n as u64;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    dst.writable().await?;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        if eof {
            unsafe {
                libc::shutdown(dst_fd, libc::SHUT_WR);
            }
            return Ok(total);
        }

        let read = src.try_io(Interest::READABLE, || {
            raw_splice(src_fd, pipe.write_fd, SPLICE_CHUNK)
        });
        match read {
            Ok(0) => {
                eof = true;
            }
            Ok(n) => {
                in_pipe += n;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                src.readable().await?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Zero-copy bidirectional kernel `splice(2)` bridge between client and backend TCP sockets.
pub async fn splice_bidirectional(client: TcpStream, backend: TcpStream) -> io::Result<(u64, u64)> {
    tune_tcp_stream(&client);
    tune_tcp_stream(&backend);

    let c2b = splice_one_way(&client, &backend);
    let b2c = splice_one_way(&backend, &client);
    let (up, down) = tokio::join!(c2b, b2c);
    Ok((up.unwrap_or(0), down.unwrap_or(0)))
}
