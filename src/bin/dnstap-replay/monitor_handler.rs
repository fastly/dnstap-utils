// Copyright 2021-2022 Fastly, Inc.

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use inotify::{Event, Inotify, WatchDescriptor, WatchMask};
use log::*;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Monitor status files for changes and detect when all status files are identical.
pub struct MonitorHandler {
    inotify: Inotify,
    monitors: Vec<FileMonitor>,
    delay: u64,
}

impl MonitorHandler {
    /// Create a new [`MonitorHandler`] that watches the set of status files specified in
    /// `monitor_files`.
    pub fn new(monitor_files: &[PathBuf], delay: u64) -> Result<Self> {
        let inotify = Inotify::init().context("Failed to initialize inotify")?;

        let mut monitor = MonitorHandler {
            inotify,
            monitors: vec![],
            delay,
        };

        for path in monitor_files {
            monitor.add_watch(path)?;
        }

        Ok(monitor)
    }

    /// Perform status file monitoring.
    pub async fn run(&mut self, status: Arc<AtomicBool>) -> Result<()> {
        let mut buffer = [0; 1024];
        let mut stream = self.inotify.event_stream(&mut buffer)?;

        // Perform an initial check of the current status files, if any. Since inotify is
        // event-driven, events won't be received for pre-existing status files.
        let res = self.check().await;

        // Update the match status flag and metric.
        status.store(res, Ordering::Relaxed);
        crate::metrics::MATCH_STATUS.set(res as i64);

        while let Some(event_or_error) = stream.next().await {
            match event_or_error {
                Ok(event) => {
                    // Handle this inotify event.
                    self.handle_event(event);

                    // And then re-check the status files.
                    let res = self.check().await;

                    // Update the match status flag and metric.
                    status.store(res, Ordering::Relaxed);
                    crate::metrics::MATCH_STATUS.set(res as i64);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                _ => {
                    panic!("Error while reading inotify events");
                }
            }
        }

        Ok(())
    }

    /// Add a file path to the set of status files to monitor.
    fn add_watch<P: AsRef<Path>>(&mut self, watch_path: P) -> Result<()> {
        info!("Monitoring '{}' for changes", watch_path.as_ref().display());
        let mut monitor = FileMonitor::new(&mut self.inotify, watch_path)?;
        monitor.update();
        self.monitors.push(monitor);
        Ok(())
    }

    /// Check if all of the status files being monitored have identical contents.
    async fn check(&self) -> bool {
        let res = match self.monitors.first() {
            Some(first) => self.monitors.iter().all(|item| item == first),
            None => false,
        };
        // Sleep for the configured match delay. This should be set to a large enough value to
        // allow pending dnstap payloads to be drained and suppressed.
        if res && self.delay > 0 {
            sleep(Duration::from_millis(self.delay)).await;
        }
        debug!("Monitor status: {}", res);
        res
    }

    /// Handle an inotify event.
    fn handle_event(&mut self, event: Event<OsString>) {
        debug!("Handling inotify update: {:?}", &event);
        if let Some(name) = event.name {
            for m in &mut self.monitors {
                // Look up which of the monitors have an [`inotify::WatchDescriptor`] and base
                // filename that corresponds to the inotify event being processed.
                if m.wd == event.wd && name == m.base_name {
                    // If a monitor was found, the file that it represents has been updated and its
                    // contents should be reloaded.
                    m.update();
                }
            }
        }
    }
}

/// Monitor a small file using inotify. Contains an [`inotify::WatchDescriptor`] which corresponds
/// to the directory containing the file, and caches the file's contents.
#[derive(Debug)]
struct FileMonitor {
    // The final directory component of the status file being watched, e.g. "status.txt".
    pub base_name: PathBuf,

    // The full path to the file being watched, e.g. "/run/directory/status.txt".
    pub full_name: PathBuf,

    // The WatchDescriptor returned by inotify for the directory being watched.
    pub wd: WatchDescriptor,

    // The current contents of the status file being watched.
    pub contents: Option<String>,
}

impl Eq for FileMonitor {}

impl PartialEq for FileMonitor {
    fn eq(&self, other: &Self) -> bool {
        if self.contents.is_some() && other.contents.is_some() {
            self.contents == other.contents
        } else {
            false
        }
    }
}

impl FileMonitor {
    /// Create a new [`FileMonitor`] that watches a given filesystem path and add the directory
    /// that contains it to an [`Inotify`] to be watched.
    pub fn new<P: AsRef<Path>>(inotify: &mut Inotify, watch_path: P) -> Result<FileMonitor> {
        // Figure out the canonical name of the directory that contains the filesystem path.
        let watch_dir = parent_directory_to_monitor_from_filename(&watch_path)?;

        // Extract the final directory component of `watch_path`.
        let base_name = match watch_path.as_ref().file_name() {
            Some(path) => PathBuf::from(path),
            None => bail!(
                "Unable to extract base filename from '{}'",
                watch_path.as_ref().display()
            ),
        };

        // Construct the full, canonicalized path name to the file path being monitored.
        let full_name = watch_dir.join(&base_name);

        // Watch the directory using inotify.
        let wd = inotify.add_watch(
            &watch_dir,
            WatchMask::CLOSE_WRITE
                | WatchMask::DELETE
                | WatchMask::MOVED_TO
                | WatchMask::MOVED_FROM,
        )?;

        let mut fm = FileMonitor {
            base_name,
            full_name,
            wd,
            contents: None,
        };

        // Perform an initial read of the file contents, if it already exists.
        fm.update();

        Ok(fm)
    }

    /// Read and cache the contents of the file being monitored, if it exists.
    pub fn update(&mut self) {
        self.contents = std::fs::read_to_string(&self.full_name).ok();
    }
}

fn parent_directory_to_monitor_from_filename<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    if path.as_ref().is_dir() {
        bail!(
            "Path '{}' is a directory, not a file",
            path.as_ref().display()
        );
    }
    match path.as_ref().parent() {
        Some(p) => Ok(p.canonicalize()?),
        None => bail!(format!(
            "Unable to find parent of '{}'",
            path.as_ref().display()
        )),
    }
}
