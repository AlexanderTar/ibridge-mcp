// SPDX-License-Identifier: Apache-2.0

//! A daily snapshot of the database, kept on the data volume.
//!
//! `VACUUM INTO` writes a consistent copy while the server keeps running. Copies are
//! named for the second they were taken (`ibridge-20261117T031500Z.db`), so the file
//! names sort by age and tell when the next copy is due. A restart does not take an
//! extra copy: the task waits until the newest one is a day old. Only the seven newest
//! copies are kept.
//!
//! A snapshot holds the same sealed rows as the database, so it is as safe, and as
//! sensitive, as the database file itself.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;

use crate::store::{Store, StoreError};

/// Snapshots kept.
pub const KEEP: usize = 7;
/// Time between snapshots.
const EVERY: Duration = Duration::from_hours(24);
/// Time to wait after a snapshot failed before trying again.
const RETRY: Duration = Duration::from_hours(1);
const PREFIX: &str = "ibridge-";
const SUFFIX: &str = ".db";
const PARTIAL: &str = ".partial";

/// Why a snapshot failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// The backup directory could not be used.
    #[error("could not use the backup directory: {0}")]
    Io(#[from] std::io::Error),
    /// The database could not write the copy.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Store {
    /// Writes a consistent copy of the database to `target`, which must not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Internal`] when the copy cannot be written.
    pub async fn snapshot_to(&self, target: &Path) -> Result<(), StoreError> {
        let target = target.to_str().ok_or(StoreError::Rejected)?;
        sqlx::query("VACUUM INTO ?")
            .bind(target)
            .execute(self.pool())
            .await
            .map_err(crate::store::internal)?;
        Ok(())
    }
}

/// Takes a snapshot of `store` into `dir` every day, from now on. Ends when the runtime does.
pub fn spawn_daily(store: Store, dir: PathBuf) -> JoinHandle<()> {
    spawn(dir, SystemTime::now, move |target| {
        let store = store.clone();
        async move { store.snapshot_to(&target).await.map_err(BackupError::from) }
    })
}

/// The schedule behind [`spawn_daily`], with the clock and the copy supplied.
///
/// `snapshot` must write a new file at the path it is given.
pub(crate) fn spawn<F, Fut>(
    dir: PathBuf,
    now: impl Fn() -> SystemTime + Send + 'static,
    snapshot: F,
) -> JoinHandle<()>
where
    F: Fn(PathBuf) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), BackupError>> + Send,
{
    tokio::spawn(async move {
        loop {
            let wait = match newest(&dir).await {
                Some(taken) => (taken + EVERY)
                    .duration_since(now())
                    .unwrap_or(Duration::ZERO),
                None => Duration::ZERO,
            };
            tokio::time::sleep(wait).await;
            match take(&dir, now(), &snapshot).await {
                Ok(()) => {
                    if let Err(error) = prune(&dir, KEEP).await {
                        tracing::warn!(%error, "could not remove old backups");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "backup failed; trying again in an hour");
                    tokio::time::sleep(RETRY).await;
                }
            }
        }
    })
}

/// Writes one snapshot named for `now`. The file appears under its name only when complete.
async fn take<F, Fut>(dir: &Path, now: SystemTime, snapshot: &F) -> Result<(), BackupError>
where
    F: Fn(PathBuf) -> Fut,
    Fut: Future<Output = Result<(), BackupError>>,
{
    tokio::fs::create_dir_all(dir).await?;
    let name = format!("{PREFIX}{}{SUFFIX}", stamp(now));
    let partial = dir.join(format!("{name}{PARTIAL}"));
    // A crash can leave a half-written copy behind; `VACUUM INTO` will not overwrite it.
    match tokio::fs::remove_file(&partial).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Err(error) = snapshot(partial.clone()).await {
        let _ = tokio::fs::remove_file(&partial).await;
        return Err(error);
    }
    tokio::fs::rename(&partial, dir.join(name)).await?;
    Ok(())
}

/// Snapshot files in `dir`, newest first, with when each was taken.
async fn snapshots(dir: &Path) -> Vec<(SystemTime, PathBuf)> {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return Vec::new();
    };
    let mut found = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let taken = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX))
            .and_then(parse_stamp);
        if let Some(taken) = taken {
            found.push((taken, entry.path()));
        }
    }
    found.sort_by_key(|(taken, _)| std::cmp::Reverse(*taken));
    found
}

async fn newest(dir: &Path) -> Option<SystemTime> {
    snapshots(dir).await.first().map(|(taken, _)| *taken)
}

/// Deletes all but the `keep` newest snapshots. Files that are not ours are left alone.
async fn prune(dir: &Path, keep: usize) -> std::io::Result<()> {
    for (_, path) in snapshots(dir).await.into_iter().skip(keep) {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

const DAY: i64 = 86_400;

/// `20261117T031500Z`, in UTC. Names sort by time.
fn stamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days(secs.div_euclid(DAY));
    let of_day = secs.rem_euclid(DAY);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// The time a [`stamp`] names, or `None` when `text` is not one.
fn parse_stamp(text: &str) -> Option<SystemTime> {
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if text.len() != 16 || text.get(8..9) != Some("T") || text.get(15..) != Some("Z") {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (hour, minute, second) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let secs = days_from_civil(year, month, day) * DAY + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
}

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use secrecy::SecretString;
    use tokio::time::Instant;

    use super::{BackupError, KEEP, PREFIX, parse_stamp, snapshots, spawn, stamp};
    use crate::store::{Scope, Store};

    /// 2023-11-14T22:13:20Z.
    fn base() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// The wall clock following the paused Tokio clock, so `advance` moves both.
    fn clock() -> impl Fn() -> SystemTime + Send + 'static {
        let start = Instant::now();
        move || base() + start.elapsed()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Lets the spawned task run until it waits on the clock again.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    /// A copy that is a one-line text file, so the schedule can be tested without a database.
    fn marker(target: PathBuf) -> impl Future<Output = Result<(), BackupError>> {
        std::future::ready(std::fs::write(target, "copy").map_err(BackupError::from))
    }

    #[test]
    fn stamps_name_the_utc_second_and_read_back() {
        assert_eq!(stamp(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(stamp(base()), "20231114T221320Z");
        assert_eq!(parse_stamp("20231114T221320Z"), Some(base()));
        let leap = UNIX_EPOCH + Duration::from_hours(19_782 * 24); // 2024-02-29T00:00:00Z
        assert_eq!(stamp(leap), "20240229T000000Z");
        assert_eq!(parse_stamp("20240229T000000Z"), Some(leap));
        for bad in [
            "",
            "2023",
            "20231114221320Z",
            "20231314T221320Z",
            "20231114T251320Z",
            "2023111aT221320Z",
        ] {
            assert_eq!(parse_stamp(bad), None, "{bad:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn backup_writes_vacuum_into_daily() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backups = dir.path().join("backups");
        let task = spawn(backups.clone(), clock(), marker);

        settle().await;
        assert_eq!(
            names(&backups),
            ["ibridge-20231114T221320Z.db"],
            "the first copy is taken at once"
        );

        tokio::time::advance(Duration::from_hours(23)).await;
        settle().await;
        assert_eq!(names(&backups).len(), 1, "nothing is due after 23 hours");

        tokio::time::advance(Duration::from_hours(1)).await;
        settle().await;
        assert_eq!(
            names(&backups),
            ["ibridge-20231114T221320Z.db", "ibridge-20231115T221320Z.db"],
            "a day later the second copy is taken"
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_waits_for_the_newest_copy_to_age() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backups = dir.path().join("backups");
        let first = spawn(backups.clone(), clock(), marker);
        settle().await;
        first.abort();

        tokio::time::advance(Duration::from_hours(10)).await;
        let second = spawn(backups.clone(), clock(), marker);
        settle().await;
        assert_eq!(
            names(&backups).len(),
            1,
            "a restart does not take an extra copy"
        );
        second.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn backup_rotates_keeps_7() {
        let dir = tempfile::tempdir().expect("temp dir");
        let backups = dir.path().join("backups");
        std::fs::create_dir_all(&backups).expect("dir");
        std::fs::write(backups.join("notes.txt"), "mine").expect("write");
        let task = spawn(backups.clone(), clock(), marker);
        settle().await;

        for _ in 0..9 {
            tokio::time::advance(Duration::from_hours(24)).await;
            settle().await;
        }
        let kept = snapshots(&backups).await;
        assert_eq!(kept.len(), KEEP, "ten copies were taken, seven are kept");
        let newest = stamp(base() + Duration::from_hours(24 * 9));
        let oldest = stamp(base() + Duration::from_hours(24 * 3));
        assert_eq!(
            kept.first()
                .and_then(|(_, path)| path.file_name())
                .and_then(|name| name.to_str()),
            Some(format!("{PREFIX}{newest}.db").as_str())
        );
        assert_eq!(
            kept.last()
                .and_then(|(_, path)| path.file_name())
                .and_then(|name| name.to_str()),
            Some(format!("{PREFIX}{oldest}.db").as_str()),
            "the oldest kept copy is the seventh newest"
        );
        assert!(
            names(&backups).contains(&"notes.txt".to_owned()),
            "other files are left alone"
        );
        task.abort();
    }

    #[tokio::test]
    async fn the_copy_is_a_consistent_database_with_the_rows() {
        let dir = tempfile::tempdir().expect("temp dir");
        let live = Store::open(&dir.path().join("live.db"))
            .await
            .expect("store");
        let apple = ibridge_core::AppleId::try_from("ada@icloud.com").expect("apple id");
        live.seal_under_code(
            &apple,
            &SecretString::from("pw"),
            Scope::Read,
            SystemTime::now(),
        )
        .await
        .expect("seal");

        let target = dir.path().join("copy.db");
        live.snapshot_to(&target).await.expect("snapshot");

        let copy = Store::open(&target).await.expect("the copy opens");
        copy.ready().await.expect("with this build's schema");
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(copy.pool())
            .await
            .expect("count");
        assert_eq!(accounts, 1, "the rows are in the copy");
        live.snapshot_to(&target)
            .await
            .expect_err("an existing file is never overwritten");
    }
}
