use codehealth_parser::{
    child_by_field_name, has_ancestor_kind, has_direct_child_kind, identifier_name, named_children,
    nearest_ancestor_kind, node_text, Definition, DefinitionKind, Import, ImportKind, LanguageInfo,
    LanguageParser, LanguageRegistry, QueryKind, QuerySpec, SyntaxTree,
};
use codehealth_symbols::{
    populate_structural_fingerprints, Attribute, CallSite, Definition as SymbolDefinition,
    DefinitionKind as SymbolDefinitionKind, Export, FileSymbols, FrameworkTag,
    Import as SymbolImport, Language, Parameter, ReturnType, Signature, SymbolExtractor,
    SymbolRegistry, Visibility,
};
use tree_sitter::Node;

pub const QUERY_VERSION: u32 = 1;
const DEFINITIONS_QUERY: &str = include_str!("queries/definitions.scm");
const IMPORTS_QUERY: &str = include_str!("queries/imports.scm");

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeScriptAdapter;

impl LanguageParser for TypeScriptAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "typescript",
            extensions: &["ts", "mts", "cts"],
            tree_sitter_grammar: "tree-sitter-typescript/typescript",
        }
    }

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
    }

    fn query_source(&self, kind: QueryKind) -> Option<QuerySpec> {
        query_source(kind)
    }

    fn extract_definitions(&self, tree: &SyntaxTree) -> Vec<Definition> {
        extract_definitions(tree, false)
    }

    fn extract_imports(&self, tree: &SyntaxTree) -> Vec<Import> {
        extract_imports(tree)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TsxAdapter;

impl LanguageParser for TsxAdapter {
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

    fn query_source(&self, kind: QueryKind) -> Option<QuerySpec> {
        query_source(kind)
    }

    fn extract_definitions(&self, tree: &SyntaxTree) -> Vec<Definition> {
        extract_definitions(tree, true)
    }

    fn extract_imports(&self, tree: &SyntaxTree) -> Vec<Import> {
        extract_imports(tree)
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(TypeScriptAdapter);
    registry.register(TsxAdapter);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeScriptSymbolExtractor;

impl SymbolExtractor for TypeScriptSymbolExtractor {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn extract(&self, tree: &SyntaxTree) -> FileSymbols {
        extract_symbols(tree, false)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TsxSymbolExtractor;

impl SymbolExtractor for TsxSymbolExtractor {
    fn language(&self) -> Language {
        Language::Tsx
    }

    fn extract(&self, tree: &SyntaxTree) -> FileSymbols {
        extract_symbols(tree, true)
    }
}

pub fn register_symbols(registry: &mut SymbolRegistry) {
    registry.register(TypeScriptSymbolExtractor);
    registry.register(TsxSymbolExtractor);
}

fn query_source(kind: QueryKind) -> Option<QuerySpec> {
    Some(QuerySpec {
        kind,
        version: QUERY_VERSION,
        source: match kind {
            QueryKind::Definitions => DEFINITIONS_QUERY,
            QueryKind::Imports => IMPORTS_QUERY,
        },
    })
}

fn extract_symbols(tree: &SyntaxTree, tsx: bool) -> FileSymbols {
    let language = if tsx {
        Language::Tsx
    } else {
        Language::TypeScript
    };
    let mut symbols = FileSymbols {
        path: tree.source.path.clone(),
        definitions: extract_definitions(tree, tsx)
            .into_iter()
            .map(|definition| symbol_from_parser_definition(language, tree, definition))
            .collect(),
        imports: extract_imports(tree)
            .into_iter()
            .map(|import| symbol_import_from_parser_import(language, import))
            .collect(),
        exports: Vec::new(),
        call_sites: Vec::new(),
        references: Vec::new(),
    };

    collect_type_symbols(tree.root_node(), tree, language, &mut symbols.definitions);
    collect_exports_and_calls(tree.root_node(), tree, language, &mut symbols);
    symbols.definitions.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
    });
    symbols
}

fn symbol_from_parser_definition(
    language: Language,
    tree: &SyntaxTree,
    definition: Definition,
) -> SymbolDefinition {
    let kind = match definition.kind {
        DefinitionKind::Function | DefinitionKind::ArrowFunction => SymbolDefinitionKind::Function,
        DefinitionKind::Class => SymbolDefinitionKind::Class,
        DefinitionKind::Method => SymbolDefinitionKind::Method,
        DefinitionKind::Component => SymbolDefinitionKind::ReactComponent,
        DefinitionKind::Hook => SymbolDefinitionKind::ReactHook,
        DefinitionKind::ImplMethod | DefinitionKind::TraitMethod => SymbolDefinitionKind::Method,
    };
    let qualified_name = definition
        .parent
        .as_ref()
        .map(|parent| format!("{parent}.{}", definition.name))
        .unwrap_or_else(|| definition.name.clone());
    let signature_span = signature_span(definition.span, definition.body_span);
    let mut symbol = SymbolDefinition::new(
        language,
        kind,
        definition.name,
        qualified_name,
        definition.path,
        definition.span,
    );
    symbol.body_span = definition.body_span;
    symbol.signature_span = Some(signature_span);
    symbol.visibility = if definition.exported {
        Visibility::Public
    } else {
        Visibility::Private
    };
    symbol.is_exported = definition.exported;
    symbol.is_async = definition.is_async;
    symbol.signature = parse_signature(tree.snippet(signature_span, 512).as_str());
    symbol.attributes = attributes_from_text(tree.snippet(symbol.span, 512).as_str(), symbol.span);
    add_react_tags(tree, &mut symbol);
    populate_structural_fingerprints(tree, &mut symbol);
    symbol
}

fn symbol_import_from_parser_import(language: Language, import: Import) -> SymbolImport {
    SymbolImport {
        language,
        file: import.path,
        module: import.module,
        imported_names: import.imported_names,
        span: import.span,
    }
}

fn collect_type_symbols(
    node: Node<'_>,
    tree: &SyntaxTree,
    language: Language,
    definitions: &mut Vec<SymbolDefinition>,
) {
    if matches!(
        node.kind(),
        "interface_declaration" | "type_alias_declaration"
    ) {
        if let Some((name, name_span)) = identifier_name(tree, child_by_field_name(node, "name")) {
            let kind = if node.kind() == "interface_declaration" {
                SymbolDefinitionKind::Interface
            } else {
                SymbolDefinitionKind::TypeAlias
            };
            let mut symbol = SymbolDefinition::new(
                language,
                kind,
                name.clone(),
                name,
                tree.source.path.clone(),
                tree.span_for_node(node),
            );
            symbol.signature_span = Some(tree.span_for_node(node));
            symbol.visibility = if has_ancestor_kind(node, "export_statement") {
                Visibility::Public
            } else {
                Visibility::Private
            };
            symbol.is_exported = symbol.visibility == Visibility::Public;
            symbol.body_span = Some(tree.span_for_node(node));
            symbol.attributes = vec![Attribute {
                name: "name".to_string(),
                arguments: Some(format!("{}:{}", name_span.start, name_span.end)),
                span: name_span,
            }];
            definitions.push(symbol);
        }
    }

    for child in named_children(node) {
        collect_type_symbols(child, tree, language, definitions);
    }
}

fn collect_exports_and_calls(
    node: Node<'_>,
    tree: &SyntaxTree,
    language: Language,
    symbols: &mut FileSymbols,
) {
    match node.kind() {
        "export_statement" => symbols.exports.push(Export {
            language,
            file: tree.source.path.clone(),
            name: tree
                .text_for_node(node)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string(),
            span: tree.span_for_node(node),
        }),
        "call_expression" => {
            if let Some(function) = child_by_field_name(node, "function") {
                symbols.call_sites.push(CallSite {
                    language,
                    file: tree.source.path.clone(),
                    callee: tree.text_for_node(function).to_string(),
                    span: tree.span_for_node(node),
                });
            }
        }
        _ => {}
    }

    for child in named_children(node) {
        collect_exports_and_calls(child, tree, language, symbols);
    }
}

fn signature_span(
    span: codehealth_parser::Span,
    body_span: Option<codehealth_parser::Span>,
) -> codehealth_parser::Span {
    body_span
        .map(|body| codehealth_parser::Span {
            start: span.start,
            end: body.start,
            start_position: span.start_position,
            end_position: body.start_position,
        })
        .unwrap_or(span)
}

fn parse_signature(text: &str) -> Signature {
    let generic_parameters = extract_between(text, '<', '>')
        .map(|value| split_list(&value))
        .unwrap_or_default();
    let parameters = extract_between(text, '(', ')')
        .map(|params| {
            split_list(&params)
                .into_iter()
                .filter_map(|raw| {
                    let raw = raw.trim().trim_matches(['{', '}']).trim().to_string();
                    if raw.is_empty() {
                        return None;
                    }
                    let (name, annotation) = split_once_trim(&raw, ':');
                    Some(Parameter {
                        name: name.unwrap_or(raw.as_str()).trim().to_string(),
                        type_annotation: annotation.map(str::to_string),
                        default_value: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let return_type = text
        .split(')')
        .nth(1)
        .and_then(|rest| split_once_trim(rest, ':').1)
        .map(|return_type| ReturnType {
            text: return_type
                .split(['{', '='])
                .next()
                .unwrap_or(return_type)
                .trim()
                .to_string(),
        });

    Signature {
        generic_parameters,
        parameters,
        return_type,
    }
}

fn add_react_tags(tree: &SyntaxTree, symbol: &mut SymbolDefinition) {
    let source = tree.snippet(symbol.span, 2048);
    if symbol.kind == SymbolDefinitionKind::ReactComponent {
        symbol.framework_tags.push(FrameworkTag::ReactComponent);
    }
    if symbol.kind == SymbolDefinitionKind::ReactHook {
        symbol.framework_tags.push(FrameworkTag::ReactHook);
    }
    if source.contains("memo(") || source.contains("React.memo(") {
        symbol.framework_tags.push(FrameworkTag::ReactMemo);
    }
    if source.contains("forwardRef(") {
        symbol.framework_tags.push(FrameworkTag::ReactForwardRef);
    }
    if source.contains("useState(") {
        symbol.framework_tags.push(FrameworkTag::ReactStateHook);
    }
    if source.contains("useEffect(") {
        symbol.framework_tags.push(FrameworkTag::ReactEffectHook);
    }
    if source.contains("useContext(") {
        symbol.framework_tags.push(FrameworkTag::ReactContextHook);
    }
    for name in jsx_names(&source) {
        if name
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase())
        {
            symbol
                .framework_tags
                .push(FrameworkTag::ReactChildComponent(name));
        } else {
            symbol
                .framework_tags
                .push(FrameworkTag::ReactJsxElement(name));
        }
    }
}

fn attributes_from_text(text: &str, span: codehealth_parser::Span) -> Vec<Attribute> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix('@'))
        .map(|decorator| Attribute {
            name: decorator
                .split(['(', ' '])
                .next()
                .unwrap_or(decorator)
                .to_string(),
            arguments: extract_between(decorator, '(', ')'),
            span,
        })
        .collect()
}

fn jsx_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let chars = source.char_indices().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if chars[index].1 == '<' {
            let next = chars.get(index + 1).map(|(_, ch)| *ch);
            if next.is_some_and(|ch| ch.is_ascii_alphabetic()) {
                let start = chars[index + 1].0;
                let mut end = start;
                for (byte, ch) in chars.iter().skip(index + 1) {
                    if ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.' {
                        end = *byte + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if end > start {
                    names.push(source[start..end].to_string());
                }
            }
        }
        index += 1;
    }
    names.sort();
    names.dedup();
    names
}

fn extract_between(text: &str, start: char, end: char) -> Option<String> {
    let start_index = text.find(start)?;
    let rest = &text[start_index + start.len_utf8()..];
    let end_index = rest.find(end)?;
    Some(rest[..end_index].trim().to_string())
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_once_trim(value: &str, delimiter: char) -> (Option<&str>, Option<&str>) {
    if let Some((left, right)) = value.split_once(delimiter) {
        (Some(left.trim()), Some(right.trim()))
    } else {
        (None, None)
    }
}

fn extract_definitions(tree: &SyntaxTree, tsx: bool) -> Vec<Definition> {
    let mut definitions = Vec::new();
    collect_definitions(tree.root_node(), tree, &mut definitions, None, tsx);
    definitions.sort_by(|left, right| left.span.start.cmp(&right.span.start));
    definitions
}

fn collect_definitions(
    node: Node<'_>,
    tree: &SyntaxTree,
    definitions: &mut Vec<Definition>,
    parent: Option<String>,
    tsx: bool,
) {
    match node.kind() {
        "class_declaration" => {
            let name = identifier_name(tree, child_by_field_name(node, "name"));
            if let Some((name, name_span)) = name {
                definitions.push(build_definition(
                    tree,
                    node,
                    name.clone(),
                    DefinitionKind::Class,
                    Some(name_span),
                    child_by_field_name(node, "body"),
                    parent.clone(),
                ));
                for child in named_children(node) {
                    collect_definitions(child, tree, definitions, Some(name.clone()), tsx);
                }
                return;
            }
        }
        "function_declaration" => {
            if let Some((name, name_span)) =
                identifier_name(tree, child_by_field_name(node, "name"))
            {
                let kind = function_kind(&name, tsx);
                definitions.push(build_definition(
                    tree,
                    node,
                    name.clone(),
                    kind,
                    Some(name_span),
                    child_by_field_name(node, "body"),
                    parent.clone(),
                ));
                for child in named_children(node) {
                    collect_definitions(child, tree, definitions, Some(name.clone()), tsx);
                }
                return;
            }
        }
        "method_definition" => {
            if let Some((name, name_span)) =
                identifier_name(tree, child_by_field_name(node, "name"))
            {
                definitions.push(build_definition(
                    tree,
                    node,
                    name.clone(),
                    DefinitionKind::Method,
                    Some(name_span),
                    child_by_field_name(node, "body"),
                    parent.clone(),
                ));
                for child in named_children(node) {
                    collect_definitions(child, tree, definitions, Some(name.clone()), tsx);
                }
                return;
            }
        }
        "variable_declarator" => {
            if let Some(definition) = variable_definition(tree, node, parent.clone(), tsx) {
                let child_parent = Some(definition.name.clone());
                definitions.push(definition);
                for child in named_children(node) {
                    collect_definitions(child, tree, definitions, child_parent.clone(), tsx);
                }
                return;
            }
        }
        _ => {}
    }

    for child in named_children(node) {
        collect_definitions(child, tree, definitions, parent.clone(), tsx);
    }
}

fn variable_definition(
    tree: &SyntaxTree,
    node: Node<'_>,
    parent: Option<String>,
    tsx: bool,
) -> Option<Definition> {
    let value = child_by_field_name(node, "value")?;
    let is_arrow = value.kind() == "arrow_function";
    let is_component_wrapper =
        value.kind() == "call_expression" && call_wraps_component(tree, value);
    if !is_arrow && !is_component_wrapper {
        return None;
    }

    let (name, name_span) = identifier_name(tree, child_by_field_name(node, "name"))?;
    let kind = if is_hook_name(&name) {
        DefinitionKind::Hook
    } else if tsx && (is_component_name(&name) || is_component_wrapper) {
        DefinitionKind::Component
    } else {
        DefinitionKind::ArrowFunction
    };

    Some(build_definition(
        tree,
        node,
        name,
        kind,
        Some(name_span),
        Some(value),
        parent,
    ))
}

fn build_definition(
    tree: &SyntaxTree,
    node: Node<'_>,
    name: String,
    kind: DefinitionKind,
    name_span: Option<codehealth_parser::Span>,
    body_node: Option<Node<'_>>,
    parent: Option<String>,
) -> Definition {
    Definition {
        name,
        kind,
        language: tree.source.language.name.to_string(),
        path: tree.source.path.clone(),
        span: tree.span_for_node(node),
        name_span,
        body_span: body_node.map(|body| tree.span_for_node(body)),
        exported: has_ancestor_kind(node, "export_statement"),
        is_async: is_async_node(tree, node),
        parent,
    }
}

fn function_kind(name: &str, tsx: bool) -> DefinitionKind {
    if is_hook_name(name) {
        DefinitionKind::Hook
    } else if tsx && is_component_name(name) {
        DefinitionKind::Component
    } else {
        DefinitionKind::Function
    }
}

fn is_hook_name(name: &str) -> bool {
    name.starts_with("use")
        && name
            .chars()
            .nth(3)
            .is_some_and(|character| character.is_ascii_uppercase())
}

fn is_component_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|character| character.is_ascii_uppercase())
}

fn is_async_node(tree: &SyntaxTree, node: Node<'_>) -> bool {
    has_direct_child_kind(node, "async")
        || tree.text_for_node(node).trim_start().starts_with("async ")
}

fn call_wraps_component(tree: &SyntaxTree, node: Node<'_>) -> bool {
    let text = tree.text_for_node(node);
    text.contains("memo(") || text.contains("forwardRef(") || text.contains("React.memo(")
}

fn extract_imports(tree: &SyntaxTree) -> Vec<Import> {
    let mut imports = Vec::new();
    collect_imports(tree.root_node(), tree, &mut imports);
    imports.sort_by(|left, right| left.span.start.cmp(&right.span.start));
    imports
}

fn collect_imports(node: Node<'_>, tree: &SyntaxTree, imports: &mut Vec<Import>) {
    if node.kind() == "import_statement" {
        let module = child_by_field_name(node, "source")
            .map(|source| strip_quotes(tree.text_for_node(source)))
            .unwrap_or_default();
        let imported_names = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "identifier" || child.kind() == "property_identifier")
            .map(|child| node_text(&tree.source.source, child))
            .collect::<Vec<_>>();
        imports.push(Import {
            module,
            imported_names,
            kind: ImportKind::EsModule,
            language: tree.source.language.name.to_string(),
            path: tree.source.path.clone(),
            span: tree.span_for_node(node),
        });
    }

    for child in named_children(node) {
        collect_imports(child, tree, imports);
    }
}

fn strip_quotes(value: &str) -> String {
    value.trim_matches(['"', '\'', '`']).to_string()
}

#[allow(dead_code)]
fn enclosing_class_name(tree: &SyntaxTree, node: Node<'_>) -> Option<String> {
    let class = nearest_ancestor_kind(node, &["class_declaration"])?;
    let name = child_by_field_name(class, "name")?;
    Some(tree.text_for_node(name).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_parser::{run_query, SourceFile};
    use std::path::Path;

    #[test]
    fn extracts_typescript_definitions_and_imports() {
        let parser = TypeScriptAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/typescript/definitions.ts");
        let source = std::fs::read_to_string(&path).expect("fixture");
        let source_file = SourceFile::new(path, parser.info(), source);
        let tree = parser.parse(&source_file).expect("parse");

        let definitions = parser.extract_definitions(&tree);
        let query_matches = run_query(
            parser.tree_sitter_language().expect("language"),
            &tree,
            parser
                .query_source(QueryKind::Definitions)
                .expect("definitions query"),
        )
        .expect("query");

        assert!(definitions
            .iter()
            .any(|definition| definition.name == "add"));
        assert!(definitions
            .iter()
            .any(|definition| definition.name == "Worker"));
        assert!(definitions
            .iter()
            .any(|definition| definition.name == "mapValue"));
        assert!(!query_matches.is_empty());
        assert!(!tree.has_error());
    }

    #[test]
    fn extracts_tsx_components() {
        let parser = TsxAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/tsx/components.tsx");
        let source = std::fs::read_to_string(&path).expect("fixture");
        let source_file = SourceFile::new(path, parser.info(), source);
        let tree = parser.parse(&source_file).expect("parse");

        let definitions = parser.extract_definitions(&tree);

        assert!(definitions.iter().any(|definition| {
            definition.name == "ProfileCard" && definition.kind == DefinitionKind::Component
        }));
        assert!(definitions.iter().any(|definition| {
            definition.name == "useProfile" && definition.kind == DefinitionKind::Hook
        }));
        assert!(!tree.has_error());
    }

    #[test]
    fn snapshots_tsx_symbols() {
        let parser = TsxAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/tsx/components.tsx");
        let source = std::fs::read_to_string(&path).expect("fixture");
        let source_file = SourceFile::new(path, parser.info(), source);
        let tree = parser.parse(&source_file).expect("parse");

        insta::assert_snapshot!(codehealth_symbols::render_symbols_snapshot(&extract_symbols(&tree, true)), @r"
tsx type_alias Props [private]
tsx react_component ProfileCard [pub]
tsx react_component InlineCard [pub]
tsx react_component MemoCard [pub]
tsx react_hook useProfile [pub]
import tsx react
");
    }
}
