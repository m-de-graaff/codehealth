use codehealth_parser::{LanguageAdapter, LanguageInfo, LanguageRegistry};

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "python",
            extensions: &["py"],
            tree_sitter_grammar: "tree-sitter-python",
        }
    }

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_python::LANGUAGE.into())
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(PythonAdapter);
}
