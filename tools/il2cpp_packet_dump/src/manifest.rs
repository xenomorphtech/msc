use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Direction;
use crate::shape::{ReadKind, ShapeOp, ShapeSpec};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VersionManifest {
    pub schema_version: u32,
    pub id: String,
    pub protocol_version: u16,
    pub artifacts: Vec<Artifact>,
    pub il2cpp: Il2CppInputs,
    pub manual_shapes: Vec<ShapeSpec>,
    #[serde(default)]
    pub observed_opaque_shapes: Vec<ObservedOpaqueShape>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedOpaqueShape {
    pub direction: Direction,
    pub opcode: u16,
    pub length: usize,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Artifact {
    pub name: String,
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Il2CppInputs {
    pub opcode_enum: String,
    pub opcode_enum_file: PathBuf,
    pub handler_attribute: String,
    pub handlers_dir: PathBuf,
    #[serde(default)]
    pub isil_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub handler_metadata_dirs: Vec<PathBuf>,
    pub reader_type: String,
    pub readers: Vec<ReaderSymbol>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReaderSymbol {
    pub method: String,
    pub rva: u64,
    pub kind: String,
    pub width: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct LoadedManifest {
    pub manifest: VersionManifest,
    pub repository_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShapeKey {
    pub direction: Direction,
    pub opcode: u16,
    pub length: Option<usize>,
}

impl LoadedManifest {
    /// Return semantic manual shapes plus explicitly labeled, exact-width opaque variants.
    ///
    /// # Errors
    ///
    /// Returns an error if an observed variant is too short to contain its opcode.
    pub fn packet_shapes(&self) -> Result<Vec<ShapeSpec>> {
        let mut shapes = self.manifest.manual_shapes.clone();
        for observed in &self.manifest.observed_opaque_shapes {
            if observed.length < 2 {
                bail!(
                    "observed opaque shape {} opcode {} has invalid length {}",
                    observed.direction,
                    observed.opcode,
                    observed.length
                );
            }
            if self.manifest.manual_shapes.iter().any(|shape| {
                shape.direction == observed.direction
                    && shape.opcode == observed.opcode
                    && shape.length == Some(observed.length)
            }) {
                continue;
            }
            shapes.push(ShapeSpec {
                name: format!(
                    "observed_{}_opcode_{}_length_{}",
                    observed.direction, observed.opcode, observed.length
                ),
                direction: observed.direction,
                opcode: observed.opcode,
                length: Some(observed.length),
                source: observed.source.clone(),
                operations: vec![
                    ShapeOp::Read {
                        name: "opcode".into(),
                        kind: ReadKind::U16,
                        equals: Some(i64::from(observed.opcode)),
                    },
                    ShapeOp::Bytes {
                        name: "opaque_body".into(),
                        length: observed.length - 2,
                        equals_hex: None,
                    },
                ],
            });
        }
        Ok(shapes)
    }

    /// Load a manifest and establish the repository root used for relative paths.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/invalid manifest or an uninferable root.
    pub fn load(path: &Path, repository_root: Option<&Path>) -> Result<Self> {
        let manifest_path = fs::canonicalize(path)
            .with_context(|| format!("failed to resolve version manifest {}", path.display()))?;
        let bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read version manifest {}", path.display()))?;
        let manifest: VersionManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid version manifest {}", path.display()))?;
        if manifest.schema_version != 1 {
            bail!(
                "unsupported manifest schema {}, expected 1",
                manifest.schema_version
            );
        }
        let root = repository_root.map_or_else(
            || {
                manifest_path
                    .parent()
                    .and_then(Path::parent)
                    .and_then(Path::parent)
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .context("cannot infer repository root; pass --repository-root")
            },
            |value| Ok(value.to_path_buf()),
        )?;
        Ok(Self {
            manifest,
            repository_root: root,
        })
    }

    #[must_use]
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.repository_root.join(path)
        }
    }

    /// Verify pinned SHA-256 values for required and available artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error when an artifact is missing, unreadable, or mismatched.
    pub fn verify_artifacts(&self, include_optional: bool) -> Result<()> {
        for artifact in &self.manifest.artifacts {
            let path = self.resolve(&artifact.path);
            if !path.exists() && !artifact.required && !include_optional {
                continue;
            }
            if !path.exists() {
                bail!(
                    "version artifact {} is missing: {}",
                    artifact.name,
                    path.display()
                );
            }
            let actual = sha256_artifact(&path)?;
            if actual != artifact.sha256.to_ascii_lowercase() {
                bail!(
                    "version artifact {} hash mismatch: expected {}, got {} ({})",
                    artifact.name,
                    artifact.sha256,
                    actual,
                    path.display()
                );
            }
        }
        Ok(())
    }
}

/// Return the lowercase SHA-256 of a file.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read artifact {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Return a stable SHA-256 for either a file or a directory tree.
///
/// Directory hashes cover every regular file's repository-relative path and
/// content digest in lexical path order.
///
/// # Errors
///
/// Returns an error when the path is neither a file nor directory, or when a
/// directory entry/file cannot be read.
pub fn sha256_artifact(path: &Path) -> Result<String> {
    if path.is_file() {
        return sha256_file(path);
    }
    if !path.is_dir() {
        bail!(
            "artifact is neither a file nor directory: {}",
            path.display()
        );
    }
    let mut files = Vec::new();
    collect_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut tree = Sha256::new();
    for (relative, absolute) in files {
        let digest = sha256_file(&absolute)?;
        tree.update(digest.as_bytes());
        tree.update(b"  ");
        tree.update(relative.as_bytes());
        tree.update(b"\n");
    }
    Ok(hex::encode(tree.finalize()))
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read artifact directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, output)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("artifact path is not UTF-8")?
                .replace('\\', "/");
            output.push((relative, path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_lowercase_and_stable() {
        let digest = hex::encode(Sha256::digest(b"maple"));
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, digest.to_ascii_lowercase());
    }
}
