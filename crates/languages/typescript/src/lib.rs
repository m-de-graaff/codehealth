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

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
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

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_typescript::LANGUAGE_TSX.into())
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(TypeScriptAdapter);
    registry.register(TsxAdapter);
}
