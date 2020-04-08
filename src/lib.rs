#![allow(warnings)]  // TODO: silence std::sync::ONCE_INIT warning: https://github.com/geofft/redhook/issues/16

use std::env;
use std::ffi::{CStr, CString};
use redhook::{hook, real};
use libc::*;

// TODO: correct default?
const DEFAULT_MODE: mode_t = 0o777;

// TODO: these 64-bit variants do the wrong thing on 32-bit systems
hook! {
    unsafe fn creat64(pathname: *const c_char, mode: mode_t) -> c_int => my_creat64 {
        my_creat(pathname, mode)
    }
}

hook! {
    unsafe fn open64(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open64 {
        my_open(pathname, flags, mode)
    }
}

hook! {
    unsafe fn openat64(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat64 {
        my_openat(dirfd, pathname, flags, mode)
    }
}
hook! {
    unsafe fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen64 {
        my_fopen(pathname, mode)
    }
}

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

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        if !read_path.starts_with("/") && (safe_getcwd().starts_with(&nobuildlitter)) {
            eprintln!("opened write directory directly");
            return real!(openat)(dirfd, pathname, flags, mode);
        }
        if safe_getcwd().starts_with("/tmp/") {
            eprintln!("opened write directory directly2");
            return real!(openat)(dirfd, pathname, flags, mode);
        }

        if dirfd != -100 {
            panic!("cannot handle non-relative dirfd: {}", dirfd);
        }

        let mut write_path: String;
        if dirfd == AT_FDCWD && !read_path.starts_with("/") {
            write_path = nobuildlitter + "/" + &safe_getcwd() + "/" + read_path;
            eprintln!("write_path: {}", write_path);
            // TODO: only do this for writes
            if (flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR {
                ensure_path(dirfd, &write_path, true);
            }
        } else {
            write_path = nobuildlitter + "/" + read_path;
        }

        // TODO: special handling for O_CREAT?
        match flags & O_ACCMODE {
            O_WRONLY => {
                eprintln!("using write path");
                read_path = &write_path;
            },
            O_RDWR => {
                // TODO: copy file from read_path to write_path then open write_path
                eprintln!("faking O_RDWR support");
                read_path = &write_path;
                //panic!("O_RDWR not handled");
            },
            O_RDONLY => {
                // check write directory, fall back to read directory.
                let fd = real!(openat)(dirfd, CString::new(write_path).unwrap().as_ptr(), flags, mode);
                if fd != -1 {
                    return fd;
                } else if unsafe { *__errno_location() } != ENOENT {
                    return -1;
                }
                eprintln!("opening read-only file in write path failed, looking up read path");
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
        let write_path = nobuildlitter + "/" + &safe_getcwd() + "/" + read_path;

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
        let read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(stat)(pathname, statbuf)
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;

        let value = real!(stat)(CString::new(write_path).unwrap().as_ptr(), statbuf);
        if value != -1 {
            eprintln!("returning write path");
            return value;
        }

        eprintln!("returning read path");
        real!(stat)(pathname, statbuf)
    }
}

hook! {
    unsafe fn lstat(pathname: *const c_char, statbuf: *mut stat) -> c_int => my_lstat {
        eprintln!("hooked lstat: {}", CStr::from_ptr(pathname).to_str().unwrap());  // TODO: remove
        let read_path = CStr::from_ptr(pathname).to_str().unwrap();
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(lstat)(pathname, statbuf)
        }

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + read_path;

        let value = real!(lstat)(CString::new(write_path).unwrap().as_ptr(), statbuf);
        if value != -1 {
            return value;
        }

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
        real!(chdir)(path)
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
        // TODO: this also needs cwd magic
        if is_special_path(&read_path) {
            eprintln!("special");
            return real!(mkdirat)(dirfd, path, mode)
        }

        // TODO: if dirfd != AT_FDCWD

        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let write_path = nobuildlitter + "/" + &safe_getcwd() + "/" + read_path;

        ensure_path(dirfd, &write_path, false);
        real!(mkdirat)(dirfd, CString::new(write_path).unwrap().as_ptr(), mode)
    }
}

hook! {
    unsafe fn rename(oldpath: *const c_char, newpath: *const c_char) -> c_int => my_rename {
        let oldpath_str = CStr::from_ptr(oldpath).to_str().unwrap();
        let newpath_str = CStr::from_ptr(newpath).to_str().unwrap();
        eprintln!("hooked rename: {} {}", oldpath_str, newpath_str);
        my_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
    }
}

hook! {
    unsafe fn renameat(olddirfd: c_int, oldpath: *const c_char,
                       newdirfd: c_int, newpath: *const c_char) -> c_int => my_renameat {
        let oldpath_str = CStr::from_ptr(oldpath).to_str().unwrap();
        let newpath_str = CStr::from_ptr(newpath).to_str().unwrap();
        eprintln!("hooked renameat: {} {} {} {}", olddirfd, oldpath_str, newdirfd, newpath_str);
        // TODO: needs relative checks
        let nobuildlitter = env::var("NOBUILDLITTER_PATH").unwrap();  // TODO: initialize during library load
        let oldpath_str = String::new() + &nobuildlitter + "/" + &safe_getcwd() + "/" + &oldpath_str;
        let newpath_str = String::new() + &nobuildlitter + "/" + &safe_getcwd() + "/" + &newpath_str;
        ensure_path(AT_FDCWD, &newpath_str, true);
        real!(renameat)(olddirfd, CString::new(oldpath_str).unwrap().as_ptr(),
                        newdirfd, CString::new(newpath_str).unwrap().as_ptr())
    }
}

hook! {
    unsafe fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen {
        let mode_str = CStr::from_ptr(mode).to_str().unwrap();
        eprintln!("hooked fopen: {} {}", CStr::from_ptr(pathname).to_str().unwrap(), mode_str);
        let open_mode = match mode_str {
            "r" => O_RDONLY,
            "rce" => O_RDONLY,  // TODO: hack
            "w" => O_CREAT|O_WRONLY|O_TRUNC,
            "w+" => O_CREAT|O_RDWR|O_TRUNC,
            _ => panic!("unhandled mode: {}", mode_str),
        };
        let fd = my_openat(AT_FDCWD, pathname, open_mode, DEFAULT_MODE);
        if fd == -1 {
            return std::ptr::null_mut();
        }
        fdopen(fd, mode)
    }
}

hook! {
    unsafe fn unsetenv(name: *const c_char) -> c_int => my_unsetenv {
        let name_str = CStr::from_ptr(name).to_str().unwrap();
        eprintln!("hooked unsetenv: {}", name_str);
        real!(unsetenv)(name)
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
fn ensure_path(dirfd: c_int, path: &str, split: bool) {
    let dirname = path.to_string();
    if split {
        let mut it = path.rsplitn(2, |c| c == '/');
        it.next();
        let dirname = match it.next() {
            Some(p) => p,
            None => panic!("unexpected path"),
        };
    }
    eprintln!("dirname: {}", dirname);
    for (i, _) in dirname.match_indices(|c| c == '/') {
        if i == 0 {
            continue;
        }
        // TODO: default mode?
        let value = unsafe { real!(mkdirat)(dirfd, CString::new(&dirname[0..i]).unwrap().as_ptr(), DEFAULT_MODE) };
        if value == -1 {
            let errno = unsafe { *__errno_location() };
            if errno != EEXIST {
                eprintln!("path: {}", path);
                eprintln!("index: {}", i);
                panic!("could not create directory: {} {}", &dirname[0..i], errno);
            }
        } else {
            eprintln!("created dir: {}", &dirname[0..i]);
        }
    }
}

fn is_special_path(path: &str) -> bool {
    path.starts_with("/dev/") || path.starts_with("/tmp/")
}

// TODO: readdir
// TODO: unlink
// TODO: rmdir
