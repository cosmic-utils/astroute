use crate::Result;
use anyhow::{Context, bail, ensure};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: CString,
    pub home: PathBuf,
}
pub fn user(uid: u32) -> Result<User> {
    let mut storage = vec![0u8; 65536];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        )
    };
    ensure!(code == 0 && !result.is_null(), "User {uid} does not exist");
    Ok(User {
        uid,
        gid: entry.pw_gid,
        name: unsafe { CStr::from_ptr(entry.pw_name) }.to_owned(),
        home: PathBuf::from(
            unsafe { CStr::from_ptr(entry.pw_dir) }
                .to_string_lossy()
                .into_owned(),
        ),
    })
}
pub fn uid() -> u32 {
    unsafe { libc::getuid() }
}
pub fn config_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return Ok(path);
    }
    Ok(user(uid())?.home.join(".config"))
}
pub fn ifindex(name: &str) -> Result<u32> {
    let name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(index != 0, "Network interface is unavailable");
    Ok(index)
}
/// Resolve privileged dependencies only from system directories, never the caller's PATH.
pub fn system_tool(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "Invalid system tool name"
    );
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let path = Path::new(directory).join(name);
        if path
            .metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return Ok(path);
        }
    }
    bail!("Required system tool is not installed: {name}")
}
/// An IPv4-only host may have no IPv6 loopback address even with AF_INET6 available.
pub fn ipv6_loopback() -> Result<bool> {
    match std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}
pub fn ipv6_supported() -> Result<bool> {
    match std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}
pub fn ip_families() -> Result<&'static [&'static str]> {
    Ok(if ipv6_supported()? {
        &["-4", "-6"]
    } else {
        &["-4"]
    })
}
pub fn mode(path: &Path, permissions: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(permissions))?;
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    mode(path, 0o700)
}
pub fn lock(path: &Path, nonblocking: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
pub fn read_limited(path: &Path, limit: usize) -> Result<String> {
    let mut data = String::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "Not a regular file: {}",
        path.display()
    );
    file.take((limit + 1) as u64).read_to_string(&mut data)?;
    ensure!(data.len() <= limit, "File is too large: {}", path.display());
    Ok(data)
}
pub fn atomic_write(path: &Path, bytes: &[u8], permissions: u32) -> Result<()> {
    let parent = path.parent().context("Settings need a parent directory")?;
    let temporary = parent.join(format!(".netguard-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(permissions)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        mode(&temporary, permissions)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}
pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}
pub fn command(args: &[String], input: Option<&str>, check: bool) -> Result<Output> {
    ensure!(!args.is_empty(), "Empty command");
    static NFT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    static IP: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    static SS: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let cache = match args[0].as_str() {
        "/usr/bin/nft" => Some((&NFT, "nft")),
        "/usr/bin/ip" => Some((&IP, "ip")),
        "/usr/bin/ss" => Some((&SS, "ss")),
        _ => None,
    };
    let executable = if let Some((cache, name)) = cache {
        if cache.get().is_none() {
            let _ = cache.set(system_tool(name)?);
        }
        cache.get().unwrap().as_path()
    } else {
        Path::new(&args[0])
    };
    let mut child = Command::new(executable)
        .args(&args[1..])
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    fn capture(mut input: impl Read) -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        input
            .by_ref()
            .take(8 * 1024 * 1024)
            .read_to_end(&mut data)?;
        std::io::copy(&mut input, &mut std::io::sink())?;
        Ok(data)
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || capture(stdout));
    let err = std::thread::spawn(move || capture(stderr));
    let writer = input.and_then(|input| {
        let mut pipe = child.stdin.take()?;
        let bytes = input.as_bytes().to_vec();
        Some(std::thread::spawn(move || pipe.write_all(&bytes)))
    });
    let deadline = Instant::now() + Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            let _ = out.join();
            let _ = err.join();
            bail!("Command timed out: {}", args[0]);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let output = Output {
        success: status.success(),
        stdout: String::from_utf8_lossy(
            &out.join()
                .map_err(|_| anyhow::anyhow!("Output reader failed"))??,
        )
        .into_owned(),
        stderr: String::from_utf8_lossy(
            &err.join()
                .map_err(|_| anyhow::anyhow!("Error reader failed"))??,
        )
        .into_owned(),
    };
    if check && !output.success {
        bail!(
            "{}",
            if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            }
        );
    }
    Ok(output)
}
pub fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
pub fn which(name: &str, path: Option<&str>) -> PathBuf {
    if name.contains('/') {
        return PathBuf::from(name);
    }
    for directory in path.unwrap_or("/usr/local/bin:/usr/bin:/bin").split(':') {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file()
            && candidate
                .metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        {
            return candidate;
        }
    }
    PathBuf::from(name)
}
pub fn realpath(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}
pub fn helper_path() -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let sibling = current
        .parent()
        .context("Missing executable directory")?
        .join("astroute-helper");
    if sibling.exists() {
        return Ok(sibling);
    }
    if let Some(directory) = current.parent()
        && directory
            .file_name()
            .is_some_and(|name| name == "examples" || name == "deps")
        && let Some(parent) = directory.parent()
    {
        let built = parent.join("astroute-helper");
        if built.exists() {
            return Ok(built);
        }
    }
    let installed = PathBuf::from("/usr/libexec/astroute-helper");
    if installed.exists() {
        return Ok(installed);
    }
    bail!("Build or install astroute-helper alongside the application")
}
pub fn poll(fd: libc::c_int, milliseconds: i32) -> Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(result > 0)
}
/// Only libc calls and stack storage are used between fork and exec.
///
/// # Safety
/// Call in the child of a single-threaded launcher before exec, with a writable
/// cgroup.procs descriptor and prepared user/directory values.
unsafe fn enter(group: i32, user: &User, home: &CString) -> std::io::Result<()> {
    let mut bytes = [0u8; 24];
    let mut offset = bytes.len();
    let mut pid = unsafe { libc::getpid() } as u32;
    loop {
        offset -= 1;
        bytes[offset] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let length = bytes.len() - offset;
    if unsafe { libc::write(group, bytes[offset..].as_ptr().cast(), length) } != length as isize {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::initgroups(user.name.as_ptr(), user.gid) } != 0
        || unsafe { libc::setresgid(user.gid, user.gid, user.gid) } != 0
        || unsafe { libc::setresuid(user.uid, user.uid, user.uid) } != 0
        || unsafe { libc::chdir(home.as_ptr()) } != 0
        || unsafe { libc::setsid() } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
pub fn spawn_worker(user: &User, group: &Path) -> Result<std::process::Child> {
    let group = OpenOptions::new()
        .write(true)
        .open(group.join("cgroup.procs"))?;
    let user = user.clone();
    let home = CString::new(user.home.as_os_str().as_encoded_bytes())?;
    let mut command = Command::new(helper_path()?);
    command
        .arg("--proxy-worker")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &user.home)
        .env("LANG", "C.UTF-8");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            enter(group.as_raw_fd(), &user, &home)?;
            // Credential changes clear PDEATHSIG, so arm it after dropping privileges.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    Ok(command.spawn()?)
}
pub fn spawn_gated(
    user: &User,
    group: &Path,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    directory: &Path,
) -> Result<(u32, File)> {
    ensure!(!argv.is_empty(), "No launch command");
    let executable = CString::new(
        which(&argv[0], environment.get("PATH").map(String::as_str))
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    let arguments: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<std::result::Result<_, _>>()?;
    let env: Vec<CString> = environment
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<std::result::Result<_, _>>()?;
    let mut argptr: Vec<_> = arguments.iter().map(|s| s.as_ptr()).collect();
    argptr.push(std::ptr::null());
    let mut envptr: Vec<_> = env.iter().map(|s| s.as_ptr()).collect();
    envptr.push(std::ptr::null());
    let home = CString::new(directory.as_os_str().as_encoded_bytes())?;
    let null = CString::new("/dev/null")?;
    let group = OpenOptions::new()
        .write(true)
        .open(group.join("cgroup.procs"))?;
    let mut pipes = [0; 2];
    ensure!(
        unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
        "Unable to prepare app launch"
    );
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(pipes[1]);
            let mut ready = 0u8;
            if libc::read(pipes[0], (&mut ready as *mut u8).cast(), 1) != 1 || ready != b'1' {
                libc::_exit(125);
            }
            libc::close(pipes[0]);
            if enter(group.as_raw_fd(), user, &home).is_err() {
                libc::_exit(126);
            }
            let fd = libc::open(null.as_ptr(), libc::O_RDWR);
            if fd < 0 {
                libc::_exit(126);
            }
            for target in 0..3 {
                if libc::dup2(fd, target) < 0 {
                    libc::_exit(126);
                }
            }
            // close_range is available on the kernels needed by nft socket cgroup matching.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) < 0 {
                libc::_exit(126);
            }
            libc::execve(executable.as_ptr(), argptr.as_ptr(), envptr.as_ptr());
            libc::_exit(126);
        }
    }
    unsafe {
        libc::close(pipes[0]);
    }
    if pid < 0 {
        unsafe {
            libc::close(pipes[1]);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((pid as u32, unsafe { File::from_raw_fd(pipes[1]) }))
}
