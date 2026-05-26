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
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(RustAdapter);
}
