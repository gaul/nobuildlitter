#![allow(warnings)]  // TODO: silence std::sync::ONCE_INIT warning: https://github.com/geofft/redhook/issues/16

use std::env;
use std::ffi::{CStr, CString};
use redhook::{hook, real};
use libc::*;

hook! {
    unsafe fn creat(pathname: *const c_char, mode: mode_t) -> c_int => my_creat {
        eprintln!("hooked creat: \"{}\" {:#o}", CStr::from_ptr(pathname).to_str().unwrap(), mode);  // TODO: remove
        my_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode)
    }
}

hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open {
        eprintln!("hooked open: \"{}\" {:#x} {:#o}", CStr::from_ptr(pathname).to_str().unwrap(), flags, mode);  // TODO: remove
        my_openat(AT_FDCWD, pathname, flags, mode)
    }
}

hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat {
        eprintln!("hooked openat: dirfd: {} path: \"{}\" flags: {:#x} mode: {:#o}", dirfd, CStr::from_ptr(pathname).to_str().unwrap(), flags, mode);  // TODO: remove
        let mut read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(openat)(dirfd, pathname, flags, mode);
        }

        if dirfd != -100 {
            panic!("cannot handle non-relative dirfd: {}", dirfd);
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let mut write_path: String;
        if dirfd == AT_FDCWD {
            write_path = nobuildlitter + "/" + &safe_getcwd() + "/" + read_path;
            eprintln!("write_path: {}", write_path);
            // TODO: only do this for writes
            if (flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR {
                ensure_path(dirfd, &write_path);
            }
        } else {
            write_path = nobuildlitter + "/" + read_path;
        }

        // TODO: special handling for O_CREAT?
        match flags & O_ACCMODE {
            O_WRONLY => read_path = &write_path,
            O_RDWR => {
                // TODO: copy file from read_path to write_path then open write_path
                read_path = &write_path;
                //panic!("O_RDWR not handled");
            },
            O_RDONLY => {
                // check write directory, fall back to read directory.
                let fd = real!(openat)(dirfd, CString::new(write_path).unwrap().as_ptr(), flags, mode);
                if fd != -1 {  // TODO: check errno
                    return fd;
                }
                eprintln!("write path failed, looking up read path");
            },
            _ => panic!("cannot happen"),
        }
        real!(openat)(dirfd, CString::new(read_path).unwrap().as_ptr(), flags, mode)
    }
}

hook! {
    unsafe fn access(pathname: *const c_char, mode: c_int) -> c_int => my_access {
        eprintln!("hooked access: {} {:#x}", CStr::from_ptr(pathname).to_str().unwrap(), mode);  // TODO: remove
        my_faccessat(AT_FDCWD, pathname, mode, 0)
    }
}

hook! {
    unsafe fn faccessat(dirfd: c_int, pathname: *const c_char, mode: c_int, flags: c_int) -> c_int => my_faccessat {
        eprintln!("hooked faccessat: {} {} {:#x} {:#x}", dirfd, CStr::from_ptr(pathname).to_str().unwrap(), mode, flags);  // TODO: remove
        let read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(faccessat)(dirfd, pathname, mode, flags)
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;

        let value = real!(faccessat)(dirfd, CString::new(write_path).unwrap().as_ptr(), mode, flags);
        if value != -1 {
            return value;
        }
        real!(faccessat)(dirfd, CString::new(read_path).unwrap().as_ptr(), mode, flags)
    }
}

hook! {
    unsafe fn stat(pathname: *const c_char, statbuf: *mut stat) -> c_int => my_stat {
        eprintln!("hooked stat: {}", CStr::from_ptr(pathname).to_str().unwrap());  // TODO: remove
        // TODO: check writepath
        real!(stat)(pathname, statbuf)
    }
}

hook! {
    unsafe fn lstat(pathname: *const c_char, statbuf: *mut stat) -> c_int => my_lstat {
        eprintln!("hooked lstat: {}", CStr::from_ptr(pathname).to_str().unwrap());  // TODO: remove
        // TODO: check writepath
        real!(lstat)(pathname, statbuf)
    }
}

hook! {
    unsafe fn fstatat(dirfd: c_int, pathname: *const c_char, statbuf: *mut stat, flags: c_int) -> c_int => my_fstatat {
        eprintln!("hooked fstatat: {} {} {:#x}", dirfd, CStr::from_ptr(pathname).to_str().unwrap(), flags);  // TODO: remove
        let read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(fstatat)(dirfd, pathname, statbuf, flags)
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;

        let value = real!(fstatat)(dirfd, CString::new(write_path).unwrap().as_ptr(), statbuf, flags);
        if value != -1 {
            return value;
        }
        real!(fstatat)(dirfd, CString::new(read_path).unwrap().as_ptr(), statbuf, flags)
    }
}

// TODO: this shouldn't be hooked, instead all path creation should look at getcwd
hook! {
    unsafe fn chdir(path: *const c_char) -> c_int => my_chdir {
        // TODO: what if switching to a write directory?
        eprintln!("chdir: {}", CStr::from_ptr(path).to_str().unwrap());
        //panic!("unhandled chdir: {}", CStr::from_ptr(path).to_str().unwrap())
        let res = real!(chdir)(path);
        eprintln!("chdir res: {}", res);
        res
    }
}
/*
*/

hook! {
    unsafe fn chroot(path: *const c_char) -> c_int => my_chroot {
        panic!("unhandled chroot: {}", CStr::from_ptr(path).to_str().unwrap())
    }
}

hook! {
    unsafe fn mkdir(path: *const c_char, mode: mode_t) -> c_int => my_mkdir {
        eprintln!("hooked mkdir: {} {:#o}", CStr::from_ptr(path).to_str().unwrap(), mode);  // TODO: remove
        my_mkdirat(AT_FDCWD, path, mode)
    }
}

hook! {
    unsafe fn mkdirat(dirfd: c_int, path: *const c_char, mode: mode_t) -> c_int => my_mkdirat {
        eprintln!("hooked mkdirat: {} {} {:#o}", dirfd, CStr::from_ptr(path).to_str().unwrap(), mode);  // TODO: remove
        let read_path = CStr::from_ptr(path).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(mkdirat)(dirfd, path, mode)
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;

        let value = real!(mkdirat)(dirfd, CString::new(write_path).unwrap().as_ptr(), mode);
        if value != -1 {
            return value;
        }
        // TODO: this doesn't seem right, only mkdir in the write_path
        real!(mkdirat)(dirfd, CString::new(read_path).unwrap().as_ptr(), mode)
    }
}

fn safe_getcwd() -> String {
    let len = PATH_MAX as size_t;
    let buf = unsafe { malloc(len) };
    let res = unsafe { getcwd(buf as *mut c_char, len) };
    if res == std::ptr::null_mut() {
        panic!("getcwd failed");
    }
    let cwd = unsafe { CStr::from_ptr(buf as *mut c_char).to_str().unwrap().to_string() };
    eprintln!("safe_getcwd: {}", cwd);
    unsafe { free(buf) };
    cwd
}

// mkdir -p equivalent
fn ensure_path(dirfd: c_int, path: &str) {
    let mut it = path.rsplitn(2, |c| c == '/');
    it.next();
    let dirname = match it.next() {
        Some(p) => p,
        None => panic!("unexpected path"),
    };
    eprintln!("dirname: {}", dirname);
    for (i, _) in dirname.match_indices(|c| c == '/') {
        if i == 0 {
            continue;
        }
        // TODO: default mode?
        let value = unsafe { real!(mkdirat)(dirfd, CString::new(&dirname[0..i]).unwrap().as_ptr(), 0o777) };
        if value == -1 {
            let errno = unsafe { *__errno_location() };
            if errno != EEXIST {
                eprintln!("path: {}", path);
                eprintln!("index: {}", i);
                panic!("could not create directory: {} {}", &dirname[0..i], errno);
            }
        }
    }
}

fn is_special_path(path: &str) -> bool {
    path.starts_with("/dev/") || path.starts_with("/tmp/")
}

// TODO: ensure directory hierarchy exists
// TODO: readdir
// TODO: unlink
// TODO: rmdir
// TODO: how to redirect openat to correct directory?
