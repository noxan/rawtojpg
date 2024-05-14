use anyhow::{ensure, Context, Result};
use clap::Parser;
use futures::stream::StreamExt;
use memmap2::{Mmap, MmapOptions};
use nix::fcntl::posix_fadvise;
use nix::fcntl::PosixFadviseAdvice;
use nix::sys::mman::{madvise, MmapAdvise};
use nix::unistd::{sysconf, SysconfVar};
use once_cell::sync::OnceCell;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReadDirStream;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Input directory containing RAW files
    input_dir: PathBuf,

    /// Output directory to store extracted JPEGs
    #[arg(default_value = ".")]
    output_dir: PathBuf,

    /// How many files to process at once
    #[arg(short, long, default_value_t = 8)]
    transfers: usize,

    /// Look for this extension in addition to the default list.
    ///
    /// Default list: arw, cr2, crw, dng, erf, kdc, mef, mrw, nef, nrw, orf, pef, raf, raw, rw2,
    /// rwl, sr2, srf, srw, x3f
    #[arg(short, long)]
    extension: Option<OsString>,
}

const fn is_jpeg_soi(buf: &[u8]) -> bool {
    buf[0] == 0xff && buf[1] == 0xd8
}

unsafe fn madvise_aligned(addr: *mut u8, length: usize, advice: MmapAdvise) -> Result<()> {
    static PAGE_SIZE: OnceCell<usize> = OnceCell::new();

    let page_size = *PAGE_SIZE.get_or_try_init(|| {
        sysconf(SysconfVar::PAGE_SIZE)
            .context("Failed to get page size")?
            .context("PAGE_SIZE is not available")
            .map(|v| v as usize)
    })?;

    let page_aligned_start = (addr as usize) & !(page_size - 1);

    let original_end = addr as usize + length;
    let page_aligned_end = (original_end + page_size - 1) & !(page_size - 1);

    let aligned_length = page_aligned_end - page_aligned_start;
    let aligned_addr = page_aligned_start as *mut _;
    let aligned_nonnull = NonNull::new(aligned_addr).context("Aligned address was NULL")?;

    Ok(madvise(aligned_nonnull, aligned_length, advice)?)
}

async fn mmap_raw(raw_fd: i32) -> Result<Mmap> {
    // We only access a small part of the file, don't read in more than necessary.
    posix_fadvise(raw_fd, 0, 0, PosixFadviseAdvice::POSIX_FADV_RANDOM)?;

    let raw_buf = unsafe { MmapOptions::new().map(raw_fd)? };

    unsafe {
        madvise_aligned(
            raw_buf.as_ptr() as *mut _,
            raw_buf.len(),
            MmapAdvise::MADV_RANDOM,
        )?;
    }

    Ok(raw_buf)
}

fn extract_jpeg(raw_fd: i32, raw_buf: &[u8]) -> Result<&[u8]> {
    let exif = rexif::parse_buffer(raw_buf)?;
    let jpeg_offset_tag = 0x0201; // JPEGInterchangeFormat
    let jpeg_length_tag = 0x0202; // JPEGInterchangeFormatLength
    let mut jpeg_offset = None;
    let mut jpeg_sz = None;

    for entry in &exif.entries {
        if entry.ifd.tag == jpeg_offset_tag {
            jpeg_offset = Some(entry.value.to_i64(0).context("Invalid EXIF type")? as usize);
        } else if entry.ifd.tag == jpeg_length_tag {
            jpeg_sz = Some(entry.value.to_i64(0).context("Invalid EXIF type")? as usize);
        }
        if jpeg_offset.is_some() && jpeg_sz.is_some() {
            break;
        }
    }

    let jpeg_offset = jpeg_offset.context("Cannot find embedded JPEG")?;
    let jpeg_sz = jpeg_sz.context("Cannot find embedded JPEG")?;

    ensure!(
        (jpeg_offset + jpeg_sz) <= raw_buf.len(),
        "JPEG data exceeds file size"
    );
    ensure!(
        is_jpeg_soi(&raw_buf[jpeg_offset..]),
        "Missing JPEG SOI marker"
    );

    posix_fadvise(
        raw_fd,
        jpeg_offset as i64,
        jpeg_sz as i64,
        PosixFadviseAdvice::POSIX_FADV_WILLNEED,
    )?;

    unsafe {
        let em_jpeg_ptr = raw_buf.as_ptr().add(jpeg_offset);
        madvise_aligned(em_jpeg_ptr as *mut _, jpeg_sz, MmapAdvise::MADV_WILLNEED)?;
    }

    Ok(&raw_buf[jpeg_offset..jpeg_offset + jpeg_sz])
}

async fn write_jpeg(out_dir: &Path, filename: &str, jpeg_buf: &[u8]) -> Result<()> {
    let mut output_file = out_dir.join(filename);
    output_file.set_extension("jpg");
    println!("{filename}");

    let mut out_file = File::create(&output_file).await?;
    out_file.write_all(jpeg_buf).await?;
    Ok(())
}

async fn process_file(entry_path: PathBuf, out_dir: &Path) -> Result<()> {
    let filename = entry_path
        .file_name()
        .and_then(|e| e.to_str())
        .context("Invalid filename")?;
    let in_file = File::open(&entry_path).await?;
    let raw_fd = in_file.as_raw_fd();
    let raw_buf = mmap_raw(raw_fd).await?;
    let jpeg_buf = extract_jpeg(raw_fd, &raw_buf)?;
    write_jpeg(out_dir, filename, jpeg_buf).await?;
    Ok(())
}

async fn process_directory(
    in_dir: &Path,
    out_dir: &'static Path,
    ext: Option<OsString>,
    transfers: usize,
) -> Result<()> {
    let valid_extensions = [
        "arw", "cr2", "crw", "dng", "erf", "kdc", "mef", "mrw", "nef", "nrw", "orf", "pef", "raf",
        "raw", "rw2", "rwl", "sr2", "srf", "srw", "x3f",
    ]
    .iter()
    .flat_map(|&ext| {
        [
            OsStr::new(ext).to_owned(),
            OsStr::new(&ext.to_uppercase()).to_owned(),
        ]
    })
    .chain(ext.into_iter())
    .collect::<HashSet<_>>();

    let entries: Vec<_> = ReadDirStream::new(fs::read_dir(in_dir).await?)
        .filter_map(|entry| async {
            match entry {
                Ok(e)
                    if e.path()
                        .extension()
                        .map_or(false, |ext| valid_extensions.contains(ext))
                        && e.file_type().await.ok()?.is_file() =>
                {
                    Some(e.path())
                }
                _ => None,
            }
        })
        .collect()
        .await;

    let semaphore = Arc::new(Semaphore::new(transfers));
    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();

    for path in entries {
        let semaphore = semaphore.clone();
        let out_dir = out_dir.to_path_buf();
        let task = tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await?;
            let result = process_file(path, &out_dir).await;
            drop(permit);
            result
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await??;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let output_dir = Box::leak(Box::new(args.output_dir)); // It's gonna get used for each raw file and
                                                           // would need a copy for .filter_map(),
                                                           // better to just make it &'static

    fs::create_dir_all(&output_dir).await?;
    process_directory(&args.input_dir, output_dir, args.extension, args.transfers).await?;

    Ok(())
}
