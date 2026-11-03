//! When to check and which channel (U1, D1/D4): the user's update settings
//! and the anti-rollback state, kept in `settings.bin`.

/// An update channel. Each build starts on its own build's channel
/// (`0.9.7-m4.6` is a test build, `0.9.7` a stable one); the "Test builds"
/// switch moves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    Stable,
    Test,
}

impl Channel {
    pub fn name(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Test => "test",
        }
    }

    /// The channel a version name belongs to: a pre-release suffix
    /// (`-m4.6`, `-rc1`) means test.
    pub fn of_version(version: &str) -> Channel {
        if version.contains('-') {
            Channel::Test
        } else {
            Channel::Stable
        }
    }

    fn index(self) -> usize {
        match self {
            Channel::Stable => 0,
            Channel::Test => 1,
        }
    }
}

/// What asked for a check. There is no timer: only these user-visible events
/// (D1, no polling).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The app was started (desktop) or came to the foreground (Android
    /// `onStart`).
    AppStart,
    /// The desktop Devices window was shown.
    WindowOpened,
    /// Settings, "Check now".
    CheckNow,
    /// The "Test builds" switch was flipped: one check on the new channel
    /// right away, while checks are on (not limited to once a day).
    ChannelChanged,
}

/// The user's update settings plus the anti-rollback state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePrefs {
    /// Check for updates (on by default, D1).
    pub checks_on: bool,
    /// The "Test builds" switch; `None` follows the build's own channel.
    pub test_builds: Option<bool>,
    /// Windows: download and install on quit (opt-in, D5).
    pub auto_install: bool,
    /// UTC day (days since 1970) of the last completed check.
    pub last_check_day: u32,
    /// Highest manifest `seq` seen per channel ([stable, test]).
    pub seen_seq: [u64; 2],
}

impl Default for UpdatePrefs {
    fn default() -> Self {
        UpdatePrefs {
            checks_on: true,
            test_builds: None,
            auto_install: false,
            last_check_day: 0,
            seen_seq: [0, 0],
        }
    }
}

const PREFS_V1: u8 = 1;

impl UpdatePrefs {
    /// The channel this install follows.
    pub fn channel(&self, build_channel: Channel) -> Channel {
        match self.test_builds {
            Some(true) => Channel::Test,
            Some(false) => Channel::Stable,
            None => build_channel,
        }
    }

    /// Whether `trigger` may make a network request today. Automatic
    /// triggers run at most once per UTC day and only while checks are on;
    /// a channel change runs once while checks are on; "Check now" always
    /// runs.
    pub fn should_check(&self, trigger: Trigger, today: u32) -> bool {
        match trigger {
            Trigger::CheckNow => true,
            Trigger::ChannelChanged => self.checks_on,
            Trigger::AppStart | Trigger::WindowOpened => {
                self.checks_on && today != self.last_check_day
            }
        }
    }

    pub fn seen_seq(&self, channel: Channel) -> u64 {
        self.seen_seq[channel.index()]
    }

    pub(crate) fn note_seq(&mut self, channel: Channel, seq: u64) {
        let s = &mut self.seen_seq[channel.index()];
        *s = (*s).max(seq);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![PREFS_V1];
        v.push(self.checks_on as u8 | (self.auto_install as u8) << 1);
        v.push(match self.test_builds {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        v.extend_from_slice(&self.last_check_day.to_be_bytes());
        v.extend_from_slice(&self.seen_seq[0].to_be_bytes());
        v.extend_from_slice(&self.seen_seq[1].to_be_bytes());
        v
    }

    /// `None` for anything this build can't read (the defaults apply).
    pub fn decode(b: &[u8]) -> Option<UpdatePrefs> {
        if b.len() < 23 || b[0] != PREFS_V1 {
            return None;
        }
        let u64_at = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap_or([0; 8]));
        Some(UpdatePrefs {
            checks_on: b[1] & 1 != 0,
            auto_install: b[1] & 2 != 0,
            test_builds: match b[2] {
                1 => Some(false),
                2 => Some(true),
                _ => None,
            },
            last_check_day: u32::from_be_bytes(b[3..7].try_into().ok()?),
            seen_seq: [u64_at(7), u64_at(15)],
        })
    }
}

/// UTC day number of a wall-clock reading.
pub fn utc_day(now: crate::time::UnixMillis) -> u32 {
    (now.0 / 86_400_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_checks_on_auto_off() {
        let p = UpdatePrefs::default();
        assert!(p.checks_on);
        assert!(!p.auto_install);
        assert_eq!(p.test_builds, None);
    }

    #[test]
    fn channel_follows_build_until_switched() {
        assert_eq!(Channel::of_version("0.9.7-m4.6"), Channel::Test);
        assert_eq!(Channel::of_version("0.9.7"), Channel::Stable);
        let mut p = UpdatePrefs::default();
        assert_eq!(p.channel(Channel::Test), Channel::Test);
        assert_eq!(p.channel(Channel::Stable), Channel::Stable);
        p.test_builds = Some(true);
        assert_eq!(p.channel(Channel::Stable), Channel::Test);
        p.test_builds = Some(false);
        assert_eq!(p.channel(Channel::Test), Channel::Stable);
    }

    #[test]
    fn checks_only_on_events_once_a_day() {
        let mut p = UpdatePrefs::default();
        assert!(p.should_check(Trigger::AppStart, 20_000));
        assert!(p.should_check(Trigger::WindowOpened, 20_000));
        p.last_check_day = 20_000;
        assert!(!p.should_check(Trigger::AppStart, 20_000));
        assert!(!p.should_check(Trigger::WindowOpened, 20_000));
        assert!(p.should_check(Trigger::CheckNow, 20_000));
        assert!(p.should_check(Trigger::AppStart, 20_001));
        p.checks_on = false;
        assert!(!p.should_check(Trigger::AppStart, 20_001));
        assert!(!p.should_check(Trigger::WindowOpened, 20_001));
        assert!(p.should_check(Trigger::CheckNow, 20_001));
    }

    #[test]
    fn channel_change_checks_same_day_while_checks_are_on() {
        let mut p = UpdatePrefs {
            last_check_day: 20_000,
            ..UpdatePrefs::default()
        };
        assert!(p.should_check(Trigger::ChannelChanged, 20_000));
        p.checks_on = false;
        assert!(!p.should_check(Trigger::ChannelChanged, 20_000));
    }

    #[test]
    fn encode_round_trip() {
        let p = UpdatePrefs {
            checks_on: false,
            test_builds: Some(true),
            auto_install: true,
            last_check_day: 20_394,
            seen_seq: [5, u64::MAX],
        };
        assert_eq!(UpdatePrefs::decode(&p.encode()), Some(p));
        let d = UpdatePrefs::default();
        assert_eq!(UpdatePrefs::decode(&d.encode()), Some(d));
        assert_eq!(UpdatePrefs::decode(&[2; 23]), None);
        assert_eq!(UpdatePrefs::decode(&[1; 5]), None);
    }

    #[test]
    fn seq_only_goes_up() {
        let mut p = UpdatePrefs::default();
        p.note_seq(Channel::Test, 10);
        p.note_seq(Channel::Test, 3);
        assert_eq!(p.seen_seq(Channel::Test), 10);
        assert_eq!(p.seen_seq(Channel::Stable), 0);
    }
}
