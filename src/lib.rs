#![allow(warnings)]  // TODO: silence std::sync::ONCE_INIT warning: https://github.com/geofft/redhook/issues/16

use std::env;
use std::ffi::{CStr, CString};
use redhook::{hook, real};
use libc::*;

hook! {
    unsafe fn creat(pathname: *const c_char, mode: mode_t) -> c_int => my_creat {
        println!("hooked creat: \"{}\" {:#o}", CStr::from_ptr(pathname).to_str().unwrap(), mode);  // TODO: remove
        my_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode)
    }
}

hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open {
        println!("hooked open: \"{}\" {:#x} {:#o}", CStr::from_ptr(pathname).to_str().unwrap(), flags, mode);  // TODO: remove
        my_openat(AT_FDCWD, pathname, flags, mode)
    }
}

hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat {
        println!("hooked openat: dirfd: {} path: \"{}\" flags: {:#x} mode: {:#o}", dirfd, CStr::from_ptr(pathname).to_str().unwrap(), flags, mode);  // TODO: remove
        let mut read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if read_path.starts_with("/dev/") || read_path.starts_with("/tmp/") {
            // some paths are special
            return real!(openat)(dirfd, pathname, flags, mode);
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;
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
                if fd != -1 {
                    return fd;
                }
            },
            _ => panic!("cannot happen"),
        }
        real!(openat)(dirfd, CString::new(read_path).unwrap().as_ptr(), flags, mode)
    }
}

// TODO: readdir
