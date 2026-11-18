//! The app as it lives on the desktop: one process for each daemon, a tray
//! icon that brings its window back, and a notification when a request
//! waits for approval.
//!
//! The first process holds a lock beside the daemon's socket and listens
//! on a socket of its own there. A later launch finds the lock taken,
//! tells the first what it was started for ([`Ask`]) and ends. The folder
//! is the daemon's private one, so only this user's processes reach it;
//! what they can ask is to show the window or to quit, and neither hands
//! out anything.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kagebunshin::ipc::paths::{APP_LOCK_FILE as LOCK_FILE, APP_SOCKET_FILE as SOCKET_FILE};

/// How long a later launch keeps trying to reach the one that holds the
/// lock.
const REACH: Duration = Duration::from_secs(2);
/// How long the first waits for a launch that connected to say its piece.
const HEAR: Duration = Duration::from_secs(1);
/// The longest [`Ask`] read: an activation token is far shorter.
const MAX_ASK: u64 = 4096;

/// What a launch asks of the app's one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// Show the window, with the activation token the desktop gave the
    /// launch, if any, so the compositor lets it take focus.
    Show {
        token: Option<String>,
    },
    Quit,
}

impl Ask {
    fn line(&self) -> String {
        match self {
            Self::Show { token: None } => "show\n".into(),
            Self::Show { token: Some(token) } => format!("show {token}\n"),
            Self::Quit => "quit\n".into(),
        }
    }

    fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches('\n');
        match line.split_once(' ') {
            None if line == "show" => Some(Self::Show { token: None }),
            None if line == "quit" => Some(Self::Quit),
            Some(("show", token)) if !token.is_empty() => Some(Self::Show {
                token: Some(token.into()),
            }),
            _ => None,
        }
    }
}

/// The token the desktop handed this launch, on Wayland or X11. A token
/// with a newline in it is none: it would not survive [`Ask::line`].
pub fn activation_token(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"]
        .into_iter()
        .find_map(|k| env(k).filter(|t| !t.is_empty() && !t.contains('\n')))
}

/// How a launch stands to the app's one process.
pub enum Claim {
    /// This is it.
    First(Instance),
    /// Another runs, and took the [`Ask`].
    Told,
    /// None runs, and the launch only asked one to quit.
    NoneRuns,
}

/// The app's one process for the daemon whose folder is `dir`: the lock it
/// holds while it lives, and where later launches reach it.
pub struct Instance {
    _lock: File,
    listener: UnixListener,
    socket: PathBuf,
}

/// Makes this process the app's only one for the daemon whose socket is in
/// `dir`, or tells the one that runs `ask`. A process that holds the lock
/// and cannot be reached is starting or ending, so this tries again for a
/// while.
pub fn claim(dir: &Path, ask: &Ask) -> io::Result<Claim> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))?;
    let socket = dir.join(SOCKET_FILE);
    let start = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) if *ask == Ask::Quit => return Ok(Claim::NoneRuns),
            Ok(()) => break,
            Err(TryLockError::Error(e)) => return Err(e),
            Err(TryLockError::WouldBlock) => {}
        }
        match UnixStream::connect(&socket) {
            Ok(mut stream) => {
                stream.write_all(ask.line().as_bytes())?;
                return Ok(Claim::Told);
            }
            Err(e) if start.elapsed() > REACH => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    // Left by a process that was killed: no one else holds the lock.
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(Claim::First(Instance {
        _lock: lock,
        listener,
        socket,
    }))
}

impl Instance {
    /// Hands each [`Ask`] of a later launch to `on`, on a thread of its
    /// own, for as long as the process lives.
    pub fn serve(self, on: impl Fn(Ask) + Send + 'static) -> io::Result<()> {
        std::thread::Builder::new()
            .name("kagebunshin-launches".into())
            .spawn(move || {
                // The whole of it, lock included: a closure that named only
                // the listener would let the lock go when this returns.
                let Self {
                    _lock, listener, ..
                } = self;
                for stream in listener.incoming().flatten() {
                    if let Some(ask) = hear(&stream) {
                        on(ask);
                    }
                }
            })
            .map(drop)
    }

    /// Where later launches reach this one, to remove once it ends.
    pub fn socket(&self) -> PathBuf {
        self.socket.clone()
    }
}

fn hear(stream: &UnixStream) -> Option<Ask> {
    stream.set_read_timeout(Some(HEAR)).ok()?;
    let mut line = String::new();
    stream.take(MAX_ASK).read_to_string(&mut line).ok()?;
    Ask::parse(&line)
}

const OPEN: &str = "open";
const QUIT: &str = "quit";

/// The tray icon: a click, or Open in its menu, calls `show` with the
/// activation token the tray's host gave, and Quit calls `quit`. Both run
/// on the tray's thread. The icon is there until the tray is dropped.
pub fn tray(
    show: impl Fn(Option<String>) + Send + Sync + 'static,
    quit: impl Fn() + Send + Sync + 'static,
) -> Result<rune::Tray, rune::tray::TrayError> {
    let side = u32::from(MARK);
    let icon = rune::tray::TrayIcon::rgba(side, side, mark(prefers_light()));
    let spec = rune::tray::TraySpec::new("kagebunshin", "kagebunshin", icon)
        .tooltip("kagebunshin")
        .menu(vec![
            rune::tray::TrayItem::action(OPEN, "Open kagebunshin"),
            rune::tray::TrayItem::Separator,
            rune::tray::TrayItem::action(QUIT, "Quit"),
        ]);
    rune::Tray::new(spec, move |event| match event {
        rune::tray::TrayEvent::Activate { token } => show(token),
        rune::tray::TrayEvent::Menu(id) if id == OPEN => show(None),
        rune::tray::TrayEvent::Menu(id) if id == QUIT => quit(),
        _ => {}
    })
}

/// The tray mark's side, in pixels: twice what a panel of ordinary height
/// shows, so one at double scale has a pixel for each of its own.
const MARK: u16 = 64;

/// The figure the mark is drawn from, as an SVG path of straight lines.
const FIGURE: &str = include_str!("../../../packaging/icons/kagebunshin-symbolic.svg");

/// The figure's outlines, each a closed run of points in the SVG's units:
/// its path's data is `M x y L x y … Z`, once for each outline.
fn outlines() -> Vec<Vec<(f32, f32)>> {
    let data = FIGURE
        .split_once(" d=\"")
        .and_then(|(_, rest)| rest.split('"').next())
        .unwrap_or_default();
    data.split('Z')
        .map(|run| {
            let mut numbers = run.split_whitespace().filter_map(|w| w.parse().ok());
            std::iter::from_fn(|| Some((numbers.next()?, numbers.next()?))).collect()
        })
        .filter(|outline: &Vec<_>| outline.len() > 2)
        .collect()
}

/// Whether `(x, y)` is inside `outline`: a line to the right of it crosses
/// the outline an odd number of times.
fn within(outline: &[(f32, f32)], x: f32, y: f32) -> bool {
    let crossings = (outline.iter().zip(outline.iter().cycle().skip(1)))
        .filter(|((ax, ay), (bx, by))| {
            (*ay > y) != (*by > y) && x < ax + (y - ay) / (by - ay) * (bx - ax)
        })
        .count();
    crossings % 2 == 1
}

/// The figure's outlines for painting one over the other, as a window
/// does that cannot cut an opening: each with whether it is solid, and
/// each opening after what it opens. The hood is solid, the face in it is
/// an opening, and the eyes in the face are solid again.
pub fn layers() -> Vec<(Vec<(f32, f32)>, bool)> {
    let outlines = outlines();
    let mut layers: Vec<(usize, Vec<(f32, f32)>)> = (outlines.iter())
        .map(|outline| {
            let (x, y) = outline[0];
            let around = (outlines.iter())
                .filter(|other| *other != outline && within(other, x, y))
                .count();
            (around, outline.clone())
        })
        .collect();
    layers.sort_by_key(|(around, _)| *around);
    (layers.into_iter())
        .map(|(around, outline)| (outline, around % 2 == 0))
        .collect()
}

/// The tray mark as straight RGBA rows: the shadow clone, a hood with the
/// face open and two layers of clones below, as large as the square takes.
/// White, or near black where the desktop is `light`.
fn mark(light: bool) -> Vec<u8> {
    /// Points tried along each side of a pixel; the share inside the
    /// figure is how much of the pixel it covers.
    const TRIES: u16 = 4;
    /// Pixels left empty on the sides the figure reaches.
    const MARGIN: f32 = 2.0;
    let outlines = outlines();
    let span = |of: fn(&(f32, f32)) -> f32| {
        let all = || outlines.iter().flatten().map(of);
        (
            all().fold(f32::INFINITY, f32::min),
            all().fold(f32::NEG_INFINITY, f32::max),
        )
    };
    let ((left, right), (top, bottom)) = (span(|p| p.0), span(|p| p.1));
    let side = f32::from(MARK);
    // SVG units to a pixel, and the figure's middle, which goes in the
    // middle of the mark.
    let unit = (right - left).max(bottom - top) / (side - 2.0 * MARGIN);
    let middle = (f32::midpoint(left, right), f32::midpoint(top, bottom));
    // Even-odd: inside is where a line to the right crosses the outlines
    // an odd number of times.
    let inside = |x: f32, y: f32| outlines.iter().filter(|o| within(o, x, y)).count() % 2 == 1;
    let shade = if light { 0x11 } else { 0xf4 };
    (0..MARK)
        .flat_map(|y| (0..MARK).map(move |x| (x, y)))
        .flat_map(|(x, y)| {
            let at = |pixel: u16, try_: u16, middle: f32| {
                let pixels = f32::from(pixel) + (f32::from(try_) + 0.5) / f32::from(TRIES);
                (pixels - side / 2.0) * unit + middle
            };
            let hits = (0..TRIES)
                .flat_map(|j| (0..TRIES).map(move |i| (i, j)))
                .filter(|&(i, j)| inside(at(x, i, middle.0), at(y, j, middle.1)))
                .fold(0_u16, |n, _| n + 1);
            let cover = f32::from(hits) / f32::from(TRIES * TRIES);
            [shade, shade, shade, (cover * 255.0).round() as u8]
        })
        .collect()
}

/// Whether the desktop asks for a light look, by its portal's
/// `color-scheme`. Only a plain yes counts: with no answer the panel is
/// taken to be dark, as most are. Read once, since the tray's icon cannot
/// change while it shows.
fn prefers_light() -> bool {
    let read = |method: &str| {
        Command::new("busctl")
            .args(["--user", "--timeout=1", "call"])
            .args([
                "org.freedesktop.portal.Desktop",
                "/org/freedesktop/portal/desktop",
                "org.freedesktop.portal.Settings",
                method,
                "ss",
                "org.freedesktop.appearance",
                "color-scheme",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
    };
    // Older portals have no ReadOne.
    read("ReadOne")
        .or_else(|| read("Read"))
        .is_some_and(|out| says_light(&String::from_utf8_lossy(&out.stdout)))
}

/// Whether `busctl` printed a `color-scheme` of 2, light: `v u 2`, or
/// `v v u 2` from `Read`.
fn says_light(answer: &str) -> bool {
    let mut words = answer.split_whitespace().rev();
    words.next() == Some("2") && words.next() == Some("u")
}

/// Shows a desktop notification for `lasts`, where `notify-send` is
/// installed; says nothing where it is not. `summary` and `body` name
/// things, never values: notification daemons keep a history.
pub fn notify(summary: &str, body: &str, lasts: Duration) {
    let child = Command::new("notify-send")
        .args(["--app-name", "kagebunshin"])
        .args(["--expire-time", &lasts.as_millis().to_string()])
        .args(["--", summary, body])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        // Reaped off the UI thread, which must not wait on it.
        let _ = std::thread::Builder::new()
            .name("kagebunshin-notify".into())
            .spawn(move || {
                let _ = child.wait();
            });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn an_ask_survives_the_wire() {
        for ask in [
            Ask::Show { token: None },
            Ask::Show {
                token: Some("wayland-token 1".into()),
            },
            Ask::Quit,
        ] {
            assert_eq!(Ask::parse(&ask.line()), Some(ask));
        }
        for junk in ["", "show ", "quit now", "open", "\n"] {
            assert_eq!(Ask::parse(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn the_activation_token_is_wayland_s_before_x11_s() {
        let env = |vars: &'static [(&str, &str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(activation_token(env(&[])), None);
        assert_eq!(
            activation_token(env(&[
                ("DESKTOP_STARTUP_ID", "x11"),
                ("XDG_ACTIVATION_TOKEN", "wayland")
            ])),
            Some("wayland".into())
        );
        assert_eq!(
            activation_token(env(&[
                ("XDG_ACTIVATION_TOKEN", ""),
                ("DESKTOP_STARTUP_ID", "x11")
            ])),
            Some("x11".into())
        );
        assert_eq!(
            activation_token(env(&[("XDG_ACTIVATION_TOKEN", "two\nlines")])),
            None
        );
    }

    #[test]
    fn a_second_launch_tells_the_first_and_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let Claim::First(first) = claim(dir.path(), &Ask::Show { token: None }).unwrap() else {
            panic!("the first launch is the app's process");
        };
        let (tx, asks) = mpsc::channel();
        first
            .serve(move |ask| {
                let _ = tx.send(ask);
            })
            .unwrap();

        let show = Ask::Show {
            token: Some("token".into()),
        };
        assert!(matches!(claim(dir.path(), &show).unwrap(), Claim::Told));
        assert_eq!(asks.recv_timeout(Duration::from_secs(5)).unwrap(), show);
        assert!(matches!(
            claim(dir.path(), &Ask::Quit).unwrap(),
            Claim::Told
        ));
        assert_eq!(
            asks.recv_timeout(Duration::from_secs(5)).unwrap(),
            Ask::Quit
        );
    }

    #[test]
    fn quit_with_none_running_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            claim(dir.path(), &Ask::Quit).unwrap(),
            Claim::NoneRuns
        ));
        assert!(!dir.path().join(SOCKET_FILE).exists());
    }

    #[test]
    fn a_socket_left_by_a_killed_process_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        // Bound and dropped: the file stays, as after a kill, and no one
        // holds the lock.
        drop(UnixListener::bind(dir.path().join(SOCKET_FILE)).unwrap());
        assert!(matches!(
            claim(dir.path(), &Ask::Show { token: None }).unwrap(),
            Claim::First(_)
        ));
    }

    #[test]
    fn the_mark_is_a_hood_over_two_layers() {
        let pixels = mark(false);
        let side = u32::from(MARK);
        assert_eq!(pixels.len(), (side * side * 4) as usize);
        let alpha = |x: u32, y: u32| pixels[((y * side + x) * 4 + 3) as usize];
        let mid = side / 2;
        // Down the middle: the hood's point, the open face, the hood's
        // lower edge, then a gap and a layer, twice.
        let column: Vec<bool> = (0..side).map(|y| alpha(mid, y) > 127).collect();
        let runs = column.chunk_by(|a, b| a == b).filter(|run| run[0]).count();
        assert_eq!(runs, 4, "{column:?}");
        assert_eq!(alpha(mid, 6), 255);
        assert_eq!(alpha(mid, 30), 0);
        // The eyes, either side of the middle of the face.
        assert_eq!(alpha(mid - 7, 30), 255);
        assert_eq!(alpha(mid + 7, 30), 255);
        // It reaches the top and the bottom margins, and no further.
        let row = |y: u32| (0..side).any(|x| alpha(x, y) > 0);
        assert!(row(2) && row(side - 3));
        assert!(!row(1) && !row(side - 2));
        assert_eq!(alpha(0, 0), 0);
        // Light desktops get the same shape, dark.
        let dark = mark(true);
        assert!(
            pixels
                .chunks(4)
                .zip(dark.chunks(4))
                .all(|(a, b)| a[3] == b[3])
        );
        assert_eq!((pixels[0], dark[0]), (0xf4, 0x11));
    }

    /// Painted in order, the figure needs no opening cut: the hood and the
    /// two layers below it are solid, the face comes after the hood it
    /// opens, and the eyes after the face.
    #[test]
    fn the_figure_s_layers_paint_the_face_over_the_hood() {
        let solid: Vec<bool> = layers().iter().map(|(_, solid)| *solid).collect();
        assert_eq!(solid, [true, true, true, false, true, true]);
    }

    #[test]
    fn only_a_plain_light_answer_gets_the_dark_mark() {
        assert!(says_light("v u 2\n"));
        assert!(says_light("v v u 2\n"));
        for other in ["v u 1\n", "v u 0\n", "v v u 1\n", "", "v s \"2\"\n", "2"] {
            assert!(!says_light(other), "{other:?}");
        }
    }
}
