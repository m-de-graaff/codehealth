use codehealth_parser::{LanguageAdapter, LanguageInfo, LanguageRegistry};

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "typescript",
            extensions: &["ts"],
            tree_sitter_grammar: "tree-sitter-typescript/typescript",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TsxAdapter;

impl LanguageAdapter for TsxAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "tsx",
            extensions: &["tsx"],
            tree_sitter_grammar: "tree-sitter-typescript/tsx",
        }
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(TypeScriptAdapter);
    registry.register(TsxAdapter);
}
