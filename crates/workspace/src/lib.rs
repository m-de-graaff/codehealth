use codehealth_parser::{LanguageInfo, LanguageRegistry};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFile {
    pub path: PathBuf,
    pub language: LanguageInfo,
}

pub fn discover_files(
    root: impl AsRef<Path>,
    registry: &LanguageRegistry,
) -> Result<Vec<WorkspaceFile>, WorkspaceError> {
    let root = root.as_ref();
    let mut files = Vec::new();

    for entry in WalkBuilder::new(root).standard_filters(true).build() {
        let entry = entry.map_err(WorkspaceError::Walk)?;
        let is_file = entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false);

        if !is_file {
            continue;
        }

        if let Some(language) = registry.language_for_path(entry.path()) {
            files.push(WorkspaceFile {
                path: entry.path().to_path_buf(),
                language,
            });
        }
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("failed to walk workspace")]
    Walk(#[source] ignore::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_parser::{LanguageAdapter, LanguageInfo};

    struct TestAdapter;

    impl LanguageAdapter for TestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "typescript",
                extensions: &["ts"],
                tree_sitter_grammar: "tree-sitter-typescript",
            }
        }
    }

    #[test]
    fn discovers_registered_file_extensions() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/typescript");
        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);

        let files = discover_files(fixture_root, &registry).expect("fixture discovery works");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language.name, "typescript");
    }
}
