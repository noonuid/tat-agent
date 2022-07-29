use libc::{self, __exit_status, __timeval, utmpx};
use std::convert::TryFrom;
use std::ffi::CString;
use std::mem;
use std::net::{self, IpAddr};
use time::{Duration, OffsetDateTime};

pub static DEFAULT_FILE: &str = "/var/run/utmp\0";

#[repr(i16)]
#[derive(Debug, Clone, Copy)]
pub enum UtmpxType {
    // No valid user accounting information.
    Empty = 0,

    // The system's runlevel.
    RunLvl = 1,
    // Time of a system boot.
    BootTime = 2,
    // Time after system clock change.
    NewTime = 3,
    // Time when system clock changed.
    OldTime = 4,

    // Process spawned by the init process.
    InitProcess = 5,
    // Session leader of a logged in user.
    LoginProcess = 6,
    // Normal process.
    UserProcess = 7,
    // Terminated process.
    DeadProcess = 8,

    Accounting = 9,
}

impl TryFrom<i16> for UtmpxType {
    type Error = ();
    #[inline]
    fn try_from(num: i16) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::Empty),

            1 => Ok(Self::RunLvl),
            2 => Ok(Self::BootTime),
            3 => Ok(Self::NewTime),
            4 => Ok(Self::OldTime),

            5 => Ok(Self::InitProcess),
            6 => Ok(Self::LoginProcess),
            7 => Ok(Self::UserProcess),
            8 => Ok(Self::DeadProcess),

            9 => Ok(Self::Accounting),

            _ => Ok(Self::Empty),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExitStatus {
    e_termination: i16,
    e_exit: i16,
}

#[derive(Debug, Clone, Copy)]
pub struct TimeVal {
    // Seconds.
    tv_sec: i32,
    // Microseconds.
    tv_usec: i32,
}

pub fn str2i8s<const N: usize>(s: &str) -> [i8; N] {
    let mut chars = [0i8; N];
    let bytes = s.as_bytes();

    for (i, &item) in bytes.iter().enumerate() {
        if i >= N {
            break;
        }

        chars[i] = item as i8;
    }

    return chars;
}

pub fn i8s2cstring<const N: usize>(i8s: &[i8; N]) -> CString {
    // match i8s.iter().position(|b| *b == 0) {
    //     // This is safe because we manually located the first zero byte above.
    //     Some(pos) => unsafe { CString::from_raw((&mut i8s[..=pos]).as_mut_ptr()) },
    //     // This is safe because we manually generated this string.
    //     None => unsafe { CString::from_raw(([0i8]).as_mut_ptr()) },
    // }
    let s = i8s
        .iter()
        .take_while(|i| **i > 0)
        .map(|&i| i as u8 as char)
        .collect::<String>();

    CString::new(s).unwrap()
}

#[derive(Debug)]
pub struct Utmpx {
    // Type of login.
    ut_type: UtmpxType,
    // Process ID of login process.
    ut_pid: i32,
    // Devicename.
    ut_line: CString,
    // Record identifier. (Inittab ID.)
    ut_id: CString,

    // User login name.
    ut_user: CString,
    // Hostname for remote login.
    ut_host: CString,
    // Exit status of a process marked as DEAD_PROCESS.
    ut_exit: ExitStatus,

    // Session ID. (used for windowing)
    ut_session: i32,
    // The time entry was created.
    ut_tv: TimeVal,

    // Internet address of remote host. Looks like that if it's IPV4 `addr_v6[0]` is
    // non-zero and the rest is zero and if is IPV6 all indexes are non-zero.
    ut_addr_v6: [i32; 4],
}

impl Utmpx {
    // Get the type kind if the entry.
    #[inline]
    pub fn ut_type(&self) -> UtmpxType {
        self.ut_type
    }

    // Get the process ID.
    #[inline]
    pub fn ut_pid(&self) -> i32 {
        self.ut_pid
    }

    // Get the device name of the entry (usually a tty or console).
    #[inline]
    pub fn ut_line(&self) -> &str {
        self.ut_line.to_str().unwrap()
    }

    // Get the record ID.
    #[inline]
    pub fn ut_id(&self) -> &str {
        self.ut_id.to_str().unwrap()
    }

    // Get user name.
    #[inline]
    pub fn ut_user(&self) -> &str {
        self.ut_user.to_str().unwrap()
    }

    // Get host name.
    #[inline]
    pub fn ut_host(&self) -> &str {
        self.ut_host.to_str().unwrap()
    }

    #[inline]
    pub fn ut_exit(&self) -> ExitStatus {
        self.ut_exit
    }

    // Get the session ID of the entry.
    #[inline]
    pub fn ut_session(&self) -> i32 {
        self.ut_session
    }

    // Get the time where the entry was created. (often login time)
    #[inline]
    pub const fn ut_tv(&self) -> TimeVal {
        self.ut_tv
    }

    // Get the IP address of the entry.
    #[inline]
    pub fn ut_addr_v6(&self) -> IpAddr {
        match self.ut_addr_v6 {
            // In the man pages said that when it's IPV4, only the first number is set,
            // otherwise it is IPV6
            [x, 0, 0, 0] => IpAddr::V4(net::Ipv4Addr::from(x as u32)),
            [x, y, w, z] => {
                let x = x.to_be_bytes();
                let y = y.to_be_bytes();
                let w = w.to_be_bytes();
                let z = z.to_be_bytes();
                IpAddr::from([
                    x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3], w[0], w[1], w[2], w[3], z[0],
                    z[1], z[2], z[3],
                ])
            }
        }
    }

    // Get the time where the entry was created (often login time) in a more complete
    // structure.
    #[inline]
    pub fn login_time(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.ut_tv.tv_sec as i64)
            + Duration::microseconds(self.ut_tv.tv_usec as i64)
    }
}

impl From<utmpx> for Utmpx {
    // Converts [`utmpx`] to [`Utmpx`].
    #[inline]
    fn from(c_utmpx: utmpx) -> Self {
        let ut_type = match UtmpxType::try_from(c_utmpx.ut_type) {
            Ok(t) => t,
            Err(err) => panic!("{:?}", err),
        };

        let ut_exit = ExitStatus {
            e_termination: c_utmpx.ut_exit.e_termination,
            e_exit: c_utmpx.ut_exit.e_exit,
        };

        let ut_tv = TimeVal {
            tv_sec: c_utmpx.ut_tv.tv_sec,
            tv_usec: c_utmpx.ut_tv.tv_usec,
        };

        Utmpx {
            ut_type,
            ut_pid: c_utmpx.ut_pid,
            ut_line: i8s2cstring(&c_utmpx.ut_line),
            ut_id: i8s2cstring(&c_utmpx.ut_id),

            ut_user: i8s2cstring(&c_utmpx.ut_user),
            ut_host: i8s2cstring(&c_utmpx.ut_host),
            ut_exit,

            ut_session: c_utmpx.ut_session,
            ut_tv,
            ut_addr_v6: c_utmpx.ut_addr_v6,
        }
    }
}

impl From<Utmpx> for utmpx {
    // Converts [`Utmpx`] to [`utmpx`].
    #[inline]
    fn from(u: Utmpx) -> Self {
        let ut_exit = __exit_status {
            e_termination: u.ut_exit().e_termination,
            e_exit: u.ut_exit().e_exit,
        };

        let ut_tv = __timeval {
            tv_sec: u.ut_tv().tv_sec,
            tv_usec: u.ut_tv().tv_usec,
        };

        let mut ut: utmpx;
        unsafe {
            ut = mem::zeroed();

            ut.ut_type = u.ut_type as i16;
            ut.ut_pid = u.ut_pid;
            ut.ut_line = str2i8s::<32>(u.ut_line());
            ut.ut_id = str2i8s::<4>(u.ut_id());

            ut.ut_user = str2i8s::<32>(u.ut_user());
            ut.ut_host = str2i8s::<256>(u.ut_host());
            ut.ut_exit = ut_exit;

            ut.ut_session = u.ut_session;
            ut.ut_tv = ut_tv;
            ut.ut_addr_v6 = u.ut_addr_v6;
        }

        return ut;
    }
}

pub struct LoginContext {
    // pid: i32,
    // // device path of tty
    // tty_path: CString,
    // // tty_path without /dev/ prefix
    // tty_name: CString,
    // // end of the tty_path
    // tty_number: CString,

    // // current user
    // username: CString,
    // // remote machine
    // hostname: CString,

    // // remote address
    // hostaddress: [i32; 4],
    utmpx: Utmpx,
}

impl LoginContext {
    pub fn new(pid: i32, tty_path: &str, username: &str, hostname: &str) -> LoginContext {
        let ut_line = if tty_path.starts_with("/dev/") {
            &tty_path[5..]
        } else {
            tty_path
        };
        let ut_id = if ut_line.len() > 3 {
            &ut_line[3..]
        } else {
            ut_line
        };

        LoginContext {
            utmpx: Utmpx {
                ut_type: UtmpxType::UserProcess,
                ut_pid: pid,
                ut_line: CString::new(ut_line).unwrap(),
                ut_id: CString::new(ut_id).unwrap(),
                ut_user: CString::new(username).unwrap(),
                ut_host: CString::new(hostname).unwrap(),
                ut_exit: ExitStatus {
                    e_termination: 0,
                    e_exit: 0,
                },
                ut_session: 0,
                ut_tv: TimeVal {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                ut_addr_v6: [0; 4],
            },
        }
    }

    pub fn login_simple(&self) {
        unsafe {
            let ut_type = libc::USER_PROCESS;
            let ut_pid = libc::getpid();
            let ut_line: [i8; 32] = str2i8s("pts/200");
            let ut_id: [i8; 4] = str2i8s("/200");

            let ut_user: [i8; 32] = str2i8s("root");
            let ut_host: [i8; 256] = str2i8s("127.0.0.1");

            let mut ut: utmpx = mem::zeroed();

            ut.ut_type = ut_type;
            ut.ut_pid = ut_pid;
            ut.ut_line = ut_line;
            ut.ut_id = ut_id;

            ut.ut_user = ut_user;
            ut.ut_host = ut_host;

            libc::pututxline(&ut);
            libc::endutxent();
        }
    }

    pub fn login(&self) {
        unsafe {
            let mut ut: utmpx = mem::zeroed();
            let mut ut_iter: *mut utmpx;

            // let file = DEFAULT_FILE.as_ptr() as *const i8;
            // /* Tell that we want to use the UTMP file.  */
            // if libc::utmpxname(file) == -1 {
            //     return;
            // }

            libc::setutxent();

            /* Find pid in utmp.
             *
             * login sometimes overwrites the runlevel entry in /var/run/utmp,
             * confusing sysvinit. I added a test for the entry type, and the
             * problem was gone. (In a runlevel entry, st_pid is not really a pid
             * but some number calculated from the previous and current runlevel.)
             * -- Michael Riepe <michael@stud.uni-hannover.de>
             */
            loop {
                ut_iter = libc::getutxent();
                if ut_iter.is_null() {
                    break;
                }
                if (*ut_iter).ut_pid == self.utmpx.ut_pid()
                    && (*ut_iter).ut_type >= libc::INIT_PROCESS
                    && (*ut_iter).ut_type <= libc::DEAD_PROCESS
                {
                    break;
                }
            }

            /* If we can't find a pre-existing entry by pid, try by line.
             * BSD network daemons may rely on this. */
            if ut_iter.is_null() && !self.utmpx.ut_line().is_empty() {
                libc::setutxent();
                ut.ut_type = libc::LOGIN_PROCESS;
                ut.ut_line = str2i8s(self.utmpx.ut_line());
                ut_iter = libc::getutxline(&ut);
            }

            /* If we can't find a pre-existing entry by pid and line, try it by id.
             * Very stupid telnetd daemons don't set up utmp at all. (kzak) */
            if ut_iter.is_null() && !self.utmpx.ut_id().is_empty() {
                libc::setutxent();
                ut.ut_type = libc::DEAD_PROCESS;
                ut.ut_id = str2i8s(self.utmpx.ut_id());
                ut_iter = libc::getutxid(&ut);
            }

            if !ut_iter.is_null() {
                ut = *ut_iter;
            } else {
                /* some gettys/telnetds don't initialize utmp... */
                ut = mem::zeroed();
            }

            if !self.utmpx.ut_id().is_empty() && ut.ut_id[0] == 0 {
                ut.ut_id = str2i8s(self.utmpx.ut_id());
            }
            if !self.utmpx.ut_user().is_empty() {
                ut.ut_user = str2i8s(self.utmpx.ut_user());
            }
            if !self.utmpx.ut_line().is_empty() {
                ut.ut_line = str2i8s(self.utmpx.ut_line());
            }

            let now = OffsetDateTime::now_utc();
            ut.ut_tv.tv_sec = now.unix_timestamp() as i32;
            ut.ut_tv.tv_usec = now.microsecond() as i32;
            ut.ut_type = libc::USER_PROCESS;
            ut.ut_pid = self.utmpx.ut_pid();
            if !self.utmpx.ut_host().is_empty() {
                ut.ut_host = str2i8s(self.utmpx.ut_host());
                ut.ut_addr_v6 = self.utmpx.ut_addr_v6;
            }

            libc::pututxline(&ut);
            libc::endutxent();
        }
    }

    pub fn logout_simple(&self) {
        unsafe {
            let ut_type = libc::DEAD_PROCESS;
            let ut_pid = libc::getpid();
            let ut_line: [i8; 32] = str2i8s("pts/200");
            let ut_id: [i8; 4] = str2i8s("/200");

            let ut_user: [i8; 32] = str2i8s("");
            let ut_host: [i8; 256] = str2i8s("");

            let mut ut: utmpx = mem::zeroed();

            ut.ut_type = ut_type;
            ut.ut_pid = ut_pid;
            ut.ut_line = ut_line;
            ut.ut_id = ut_id;

            ut.ut_user = ut_user;
            ut.ut_host = ut_host;

            libc::pututxline(&ut);
            libc::endutxent();
        }
    }

    pub fn logout(&self) {
        unsafe {
            let mut tmp: utmpx = mem::zeroed();
            let ut: *mut utmpx;

            let file = DEFAULT_FILE.as_ptr() as *const i8;
            /* Tell that we want to use the UTMP file.  */
            if libc::utmpxname(file) == -1 {
                return;
            }

            /* Open UTMP file.  */
            libc::setutxent();

            /* Fill in search information.  */
            tmp.ut_type = libc::USER_PROCESS;
            tmp.ut_line = str2i8s(self.utmpx.ut_line());

            ut = libc::getutxline(&tmp);
            /* Read the record.  */
            if !ut.is_null() {
                /* Clear information about who & from where.  */
                (*ut).ut_user = [0; 32];
                (*ut).ut_host = [0; 256];

                let now = OffsetDateTime::now_utc();
                (*ut).ut_tv.tv_sec = now.unix_timestamp() as i32;
                (*ut).ut_tv.tv_usec = now.microsecond() as i32;

                (*ut).ut_type = libc::DEAD_PROCESS;

                libc::pututxline(ut);
            }

            /* Close UTMP file.  */
            libc::endutxent();
        }
    }
}

#[cfg(test)]
mod test {
    use super::{i8s2cstring, str2i8s, LoginContext};
    use std::{process, thread, time};

    #[test]
    fn test_str2i8s() {
        let s = "Aa\0Bb";
        let i8s: [i8; 5] = str2i8s(s);

        assert_eq!([65, 97, 0, 66, 98], i8s);
    }

    #[test]
    fn test_i8s2cstring() {
        let i8s: [i8; 5] = [65, 97, 0, 66, 98];
        let cstring = i8s2cstring(&i8s);

        assert_eq!("Aa", cstring.to_str().unwrap());
    }

    #[test]
    fn test_login_and_logout() {
        let pid = process::id() as i32;
        let lc = LoginContext::new(pid, "/dev/pts/200", "root", "127.0.0.1");

        lc.login();

        thread::sleep(time::Duration::from_secs(20));

        lc.logout();
    }

    #[test]
    fn test_login_simple() {
        let pid = process::id() as i32;
        let lc = LoginContext::new(pid, "/dev/pts/200", "root", "127.0.0.1");

        lc.login_simple();

        thread::sleep(time::Duration::from_secs(20));

        lc.logout();
    }

    #[test]
    fn test_login() {
        let pid = process::id() as i32;
        let lc = LoginContext::new(pid, "/dev/pts/200", "root", "127.0.0.1");

        lc.login();

        thread::sleep(time::Duration::from_secs(20));
    }

    #[test]
    fn test_logout_simple() {
        let pid = process::id() as i32;
        let lc = LoginContext::new(pid, "/dev/pts/200", "root", "127.0.0.1");

        lc.logout_simple();
    }

    #[test]
    fn test_logout() {
        let pid = process::id() as i32;
        let lc = LoginContext::new(pid, "/dev/pts/200", "root", "127.0.0.1");

        lc.logout();
    }
}
