use std::{fs, io};

pub fn process_start(pid: i32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // State (field 3): Z is a zombie, X dead.
    if matches!(parse_field::<char>(&stat, 0), Some('Z' | 'X')) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the process has exited",
        ));
    }
    parse_start_time(&stat)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable /proc stat"))
}

pub fn parent_pid(pid: i32) -> io::Result<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_field(&stat, 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable /proc stat"))
}

pub fn process_name(pid: i32) -> io::Result<String> {
    Ok(fs::read_to_string(format!("/proc/{pid}/comm"))?
        .trim_end()
        .to_owned())
}

/// Field `n + 3` of a stat line; see [`parse_start_time`].
fn parse_field<T: std::str::FromStr>(stat: &str, n: usize) -> Option<T> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(n)?.parse().ok()
}

/// `comm` (field 2) is in parentheses and may itself contain spaces and `)`,
/// so split after the last `)`. Field 3 is then index 0, and the start time
/// (field 22) is index 19. The parent pid (field 4) is index 1.
fn parse_start_time(stat: &str) -> Option<u64> {
    parse_field(stat, 19)
}

#[cfg(test)]
mod tests {
    use super::{parse_field, parse_start_time};

    fn line(comm: &str, start: u64) -> String {
        let mut fields: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
        fields[19] = start.to_string();
        format!("4242 ({comm}) {}", fields.join(" "))
    }

    #[test]
    fn parses_start_time_with_awkward_comm() {
        for comm in ["sh", "a b", "x) S 1 2 3", "((", ")"] {
            assert_eq!(
                parse_start_time(&line(comm, 987_654)),
                Some(987_654),
                "{comm:?}"
            );
        }
    }

    #[test]
    fn parses_parent_pid() {
        // Field 4 is "4" in `line`, whatever the comm.
        for comm in ["sh", "x) S 1 2 3"] {
            assert_eq!(parse_field::<i32>(&line(comm, 1), 1), Some(4), "{comm:?}");
        }
    }

    #[test]
    fn rejects_short_or_garbage_lines() {
        assert_eq!(parse_start_time("4242 (sh) S 1 2"), None);
        assert_eq!(parse_start_time("garbage"), None);
        assert_eq!(parse_start_time(""), None);
    }
}
