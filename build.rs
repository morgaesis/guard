use std::path::{Path, PathBuf};
use std::process::Command;

const WINDOWS_STACK_RESERVE_BYTES: u64 = 8 * 1024 * 1024;

fn git_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Emit `cargo:rerun-if-changed` for the git files that determine the embedded
/// version info. `--absolute-git-dir` resolves the real per-worktree git
/// directory (in a linked worktree `.git` is a file pointing elsewhere), and
/// `--git-path` resolves the current branch's ref file through the same
/// indirection. Watching only HEAD and the current branch ref avoids a full
/// rebuild on every unrelated ref update.
fn track_git_files() {
    let Some(git_dir) = git_stdout(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let head = Path::new(&git_dir).join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    if let Some(head_ref) = git_stdout(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(ref_path) = git_stdout(&["rev-parse", "--git-path", &head_ref]) {
            let ref_path = PathBuf::from(ref_path);
            if ref_path.exists() {
                println!("cargo:rerun-if-changed={}", ref_path.display());
            } else if let Some(packed) = git_stdout(&["rev-parse", "--git-path", "packed-refs"]) {
                // The branch ref is packed, so track the packed-refs file.
                let packed = PathBuf::from(packed);
                if packed.exists() {
                    println!("cargo:rerun-if-changed={}", packed.display());
                }
            }
        }
    }
}

/// Give the Guard process the same practical main-thread headroom on Windows
/// that it receives from common Unix defaults. The generated Clap parser and
/// async dispatch use deeper frames in unoptimized builds; the PE default can
/// otherwise exhaust the stack before argument handling begins.
fn configure_windows_stack_reserve() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let argument = match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => format!("/STACK:{WINDOWS_STACK_RESERVE_BYTES}"),
        Ok("gnu") => format!("-Wl,--stack,{WINDOWS_STACK_RESERVE_BYTES}"),
        _ => return,
    };
    println!("cargo:rustc-link-arg-bin=guard={argument}");
}

fn main() {
    let commit =
        git_stdout(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let tag = git_stdout(&["tag", "--points-at", "HEAD"]);
    let branch = git_stdout(&["branch", "--show-current"]).unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GUARD_GIT_COMMIT={}", commit);
    println!("cargo:rustc-env=GUARD_GIT_BRANCH={}", branch);
    if let Some(tag) = tag {
        println!("cargo:rustc-env=GUARD_GIT_TAG={}", tag);
    }

    track_git_files();
    configure_windows_stack_reserve();
}
