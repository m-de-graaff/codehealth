use std::path::{Path, PathBuf};
use thiserror::Error;
use tree_sitter::{Node, Query, QueryCursor, StreamingIterator, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub extensions: &'static [&'static str],
    pub tree_sitter_grammar: &'static str,
}

pub trait LanguageParser: Send + Sync {
    fn info(&self) -> LanguageInfo;

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        None
    }

    fn query_source(&self, _kind: QueryKind) -> Option<QuerySpec> {
        None
    }

    fn supports_extension(&self, extension: &str) -> bool {
        let extension = extension.trim_start_matches('.');
        self.info()
            .extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    }

    fn parse(&self, source: &SourceFile) -> ParseResult {
        let language = self
            .tree_sitter_language()
            .ok_or(ParseError::MissingGrammar {
                language: self.info().name.to_string(),
            })?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language)
            .map_err(|source| ParseError::SetLanguage {
                language: self.info().name.to_string(),
                source,
            })?;
        let tree = parser
            .parse(source.source.as_str(), None)
            .ok_or(ParseError::ParseFailed {
                path: source.path.display().to_string(),
            })?;

        Ok(SyntaxTree::new(source.clone(), tree))
    }

    fn extract_definitions(&self, _tree: &SyntaxTree) -> Vec<Definition> {
        Vec::new()
    }

    fn extract_imports(&self, _tree: &SyntaxTree) -> Vec<Import> {
        Vec::new()
    }
}

pub use LanguageParser as LanguageAdapter;

pub type ParseResult = Result<SyntaxTree, ParseError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: LanguageInfo,
    pub source: String,
}

impl SourceFile {
    pub fn new(
        path: impl Into<PathBuf>,
        language: LanguageInfo,
        source: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            language,
            source: source.into(),
        }
    }

    pub fn from_path(path: impl AsRef<Path>, language: LanguageInfo) -> Result<Self, ParseError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path).map_err(|source| ParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        Ok(Self::new(path, language, source))
    }

    pub fn byte_len(&self) -> usize {
        self.source.len()
    }
}

#[derive(Debug)]
pub struct SyntaxTree {
    pub source: SourceFile,
    tree: Tree,
    diagnostics: Vec<ParseDiagnostic>,
}

impl SyntaxTree {
    pub fn new(source: SourceFile, tree: Tree) -> Self {
        let diagnostics = collect_diagnostics(&source, tree.root_node());
        Self {
            source,
            tree,
            diagnostics,
        }
    }

    pub fn root_node(&self) -> Node<'_> {
        self.tree.root_node()
    }

    pub fn root_kind(&self) -> &str {
        self.root_node().kind()
    }

    pub fn has_error(&self) -> bool {
        self.root_node().has_error()
    }

    pub fn diagnostics(&self) -> &[ParseDiagnostic] {
        &self.diagnostics
    }

    pub fn sexp(&self) -> String {
        self.root_node().to_sexp()
    }

    pub fn span_for_node(&self, node: Node<'_>) -> Span {
        span_for_offsets(&self.source.source, node.start_byte(), node.end_byte())
    }

    pub fn text_for_node(&self, node: Node<'_>) -> &str {
        &self.source.source[node.start_byte()..node.end_byte()]
    }

    pub fn snippet(&self, span: Span, max_chars: usize) -> String {
        snippet(&self.source.source, span, max_chars)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyntaxNodeId(pub usize);

impl SyntaxNodeId {
    pub fn from_node(node: Node<'_>) -> Self {
        Self(node.id())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub start_position: LineColumn,
    pub end_position: LineColumn,
}

impl Span {
    pub fn len(self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LineColumn {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostic {
    pub message: String,
    pub span: Span,
    pub node_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub name: String,
    pub kind: DefinitionKind,
    pub language: String,
    pub path: PathBuf,
    pub span: Span,
    pub name_span: Option<Span>,
    pub body_span: Option<Span>,
    pub exported: bool,
    pub is_async: bool,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    Function,
    ArrowFunction,
    Class,
    Method,
    Component,
    Hook,
    ImplMethod,
    TraitMethod,
}

impl DefinitionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::ArrowFunction => "arrow_function",
            Self::Class => "class",
            Self::Method => "method",
            Self::Component => "component",
            Self::Hook => "hook",
            Self::ImplMethod => "impl_method",
            Self::TraitMethod => "trait_method",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub imported_names: Vec<String>,
    pub kind: ImportKind,
    pub language: String,
    pub path: PathBuf,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    EsModule,
    PythonImport,
    PythonFrom,
    RustUse,
    Unknown,
}

impl ImportKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::EsModule => "es_module",
            Self::PythonImport => "python_import",
            Self::PythonFrom => "python_from",
            Self::RustUse => "rust_use",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    Definitions,
    Imports,
}

impl QueryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Definitions => "definitions",
            Self::Imports => "imports",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuerySpec {
    pub kind: QueryKind,
    pub version: u32,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    pub pattern_index: usize,
    pub captures: Vec<QueryCapture>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryCapture {
    pub name: String,
    pub node_kind: String,
    pub text: String,
    pub span: Span,
}

pub fn run_query(
    language: tree_sitter::Language,
    tree: &SyntaxTree,
    spec: QuerySpec,
) -> Result<Vec<QueryMatch>, ParseError> {
    let query = Query::new(&language, spec.source).map_err(|source| ParseError::Query {
        language: tree.source.language.name.to_string(),
        kind: spec.kind.label().to_string(),
        source,
    })?;
    let capture_names = query
        .capture_names()
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), tree.source.source.as_bytes());
    let mut output = Vec::new();

    while let Some(query_match) = matches.next() {
        let captures = query_match
            .captures
            .iter()
            .map(|capture| {
                let node = capture.node;
                let text = tree.text_for_node(node).to_string();
                QueryCapture {
                    name: capture_names[capture.index as usize].clone(),
                    node_kind: node.kind().to_string(),
                    text,
                    span: tree.span_for_node(node),
                }
            })
            .collect::<Vec<_>>();
        output.push(QueryMatch {
            pattern_index: query_match.pattern_index,
            captures,
        });
    }

    Ok(output)
}

pub fn child_by_field_name<'tree>(node: Node<'tree>, field_name: &str) -> Option<Node<'tree>> {
    node.child_by_field_name(field_name)
}

pub fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == kind)
}

pub fn node_text(source: &str, node: Node<'_>) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

pub fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .collect()
}

pub fn has_direct_child_kind(node: Node<'_>, kind: &str) -> bool {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .any(|child| child.kind() == kind)
}

pub fn has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

pub fn nearest_ancestor_kind<'tree>(mut node: Node<'tree>, kinds: &[&str]) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if kinds.iter().any(|kind| parent.kind() == *kind) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

pub fn identifier_name(tree: &SyntaxTree, node: Option<Node<'_>>) -> Option<(String, Span)> {
    let node = node?;
    Some((
        tree.text_for_node(node).to_string(),
        tree.span_for_node(node),
    ))
}

fn collect_diagnostics(source: &SourceFile, root: Node<'_>) -> Vec<ParseDiagnostic> {
    let mut diagnostics = Vec::new();
    collect_diagnostics_from_node(source, root, &mut diagnostics);
    diagnostics
}

fn collect_diagnostics_from_node(
    source: &SourceFile,
    node: Node<'_>,
    diagnostics: &mut Vec<ParseDiagnostic>,
) {
    if node.is_error() || node.is_missing() {
        let node_kind = node.kind().to_string();
        diagnostics.push(ParseDiagnostic {
            message: if node.is_missing() {
                format!("missing {node_kind}")
            } else {
                format!("syntax error at {node_kind}")
            },
            span: span_for_offsets(&source.source, node.start_byte(), node.end_byte()),
            node_kind,
        });
    }

    for child in named_children(node) {
        collect_diagnostics_from_node(source, child, diagnostics);
    }
}

pub fn span_for_offsets(source: &str, start: usize, end: usize) -> Span {
    Span {
        start,
        end,
        start_position: line_column_for_offset(source, start),
        end_position: line_column_for_offset(source, end),
    }
}

pub fn line_column_for_offset(source: &str, byte_offset: usize) -> LineColumn {
    let bounded_offset = byte_offset.min(source.len());
    let bounded_offset = if source.is_char_boundary(bounded_offset) {
        bounded_offset
    } else {
        let mut adjusted = bounded_offset;
        while adjusted > 0 && !source.is_char_boundary(adjusted) {
            adjusted -= 1;
        }
        adjusted
    };

    let mut line = 1;
    let mut column = 1;

    for character in source[..bounded_offset].chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    LineColumn { line, column }
}

pub fn snippet(source: &str, span: Span, max_chars: usize) -> String {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len());
    if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return String::new();
    }

    let raw = &source[start..end];
    let mut snippet = raw.chars().take(max_chars).collect::<String>();
    if raw.chars().count() > max_chars {
        snippet.push_str("...");
    }
    snippet
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unsupported language for {path}")]
    UnsupportedLanguage { path: String },

    #[error("failed to read source file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("missing tree-sitter grammar for {language}")]
    MissingGrammar { language: String },

    #[error("failed to set tree-sitter language for {language}")]
    SetLanguage {
        language: String,
        #[source]
        source: tree_sitter::LanguageError,
    },

    #[error("failed to parse {path}")]
    ParseFailed { path: String },

    #[error("failed to compile {kind} query for {language}")]
    Query {
        language: String,
        kind: String,
        #[source]
        source: tree_sitter::QueryError,
    },
}

#[derive(Default)]
pub struct LanguageRegistry {
    adapters: Vec<Box<dyn LanguageParser>>,
}

impl LanguageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<A>(&mut self, adapter: A)
    where
        A: LanguageParser + 'static,
    {
        self.adapters.push(Box::new(adapter));
    }

    pub fn register_box(&mut self, adapter: Box<dyn LanguageParser>) {
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

    pub fn adapter_for_path(&self, path: &Path) -> Option<&dyn LanguageParser> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct TestParser;

    impl LanguageParser for TestParser {
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
        registry.register(TestParser);

        let language = registry
            .language_for_path(Path::new("Example.TEST"))
            .expect("extension should match");

        assert_eq!(language.name, "test");
    }

    #[test]
    fn parser_substrate_is_available() {
        let _parser = empty_tree_sitter_parser();
    }

    #[test]
    fn line_column_counts_utf8_characters() {
        let source = "a\nbé\nc";
        let offset = source.find('c').expect("fixture contains c");

        let location = line_column_for_offset(source, offset);

        assert_eq!(location, LineColumn { line: 3, column: 1 });
    }

    #[test]
    fn snippets_are_bounded() {
        let source = "0123456789";
        let span = span_for_offsets(source, 0, source.len());

        assert_eq!(snippet(source, span, 4), "0123...");
    }
}
