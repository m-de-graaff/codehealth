use codehealth_parser::{LanguageAdapter, LanguageInfo, LanguageRegistry};

#[derive(Debug, Clone, Copy, Default)]
pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "rust",
            extensions: &["rs"],
            tree_sitter_grammar: "tree-sitter-rust",
        }
    }

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_rust::LANGUAGE.into())
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(RustAdapter);
}
