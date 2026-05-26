use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub extensions: &'static [&'static str],
    pub tree_sitter_grammar: &'static str,
}

pub trait LanguageAdapter: Send + Sync {
    fn info(&self) -> LanguageInfo;

    fn supports_extension(&self, extension: &str) -> bool {
        let extension = extension.trim_start_matches('.');
        self.info()
            .extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    }

    fn parse(&self, input: ParseInput<'_>) -> Result<ParsedFile, ParseError> {
        Ok(ParsedFile {
            language: self.info(),
            byte_len: input.source.len(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParseInput<'a> {
    pub path: &'a Path,
    pub source: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFile {
    pub language: LanguageInfo,
    pub byte_len: usize,
}

#[derive(Default)]
pub struct LanguageRegistry {
    adapters: Vec<Box<dyn LanguageAdapter>>,
}

impl LanguageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<A>(&mut self, adapter: A)
    where
        A: LanguageAdapter + 'static,
    {
        self.adapters.push(Box::new(adapter));
    }

    pub fn register_box(&mut self, adapter: Box<dyn LanguageAdapter>) {
        self.adapters.push(adapter);
    }

    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }

    pub fn language_for_path(&self, path: &Path) -> Option<LanguageInfo> {
        let extension = path.extension()?.to_str()?;

        self.adapters
            .iter()
            .find(|adapter| adapter.supports_extension(extension))
            .map(|adapter| adapter.info())
    }

    pub fn adapter_for_path(&self, path: &Path) -> Option<&dyn LanguageAdapter> {
        let extension = path.extension()?.to_str()?;

        self.adapters
            .iter()
            .find(|adapter| adapter.supports_extension(extension))
            .map(Box::as_ref)
    }
}

pub fn empty_tree_sitter_parser() -> tree_sitter::Parser {
    tree_sitter::Parser::new()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("unsupported language for {path}")]
    UnsupportedLanguage { path: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAdapter;

    impl LanguageAdapter for TestAdapter {
        fn info(&self) -> LanguageInfo {
            LanguageInfo {
                name: "test",
                extensions: &["test"],
                tree_sitter_grammar: "tree-sitter-test",
            }
        }
    }

    #[test]
    fn registry_matches_extensions_case_insensitively() {
        let mut registry = LanguageRegistry::new();
        registry.register(TestAdapter);

        let language = registry
            .language_for_path(Path::new("Example.TEST"))
            .expect("extension should match");

        assert_eq!(language.name, "test");
    }

    #[test]
    fn parser_substrate_is_available() {
        let _parser = empty_tree_sitter_parser();
    }
}
