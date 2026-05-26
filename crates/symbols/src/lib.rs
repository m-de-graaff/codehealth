use codehealth_core::SourceSpan;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSummary {
    pub name: String,
    pub kind: SymbolKind,
    pub path: PathBuf,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Class,
    Method,
    Component,
    Route,
    ImplMethod,
}

pub fn extract_symbols_stub() -> Vec<SymbolSummary> {
    Vec::new()
}
