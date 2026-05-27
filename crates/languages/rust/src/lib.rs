use codehealth_parser::{
    child_by_field_name, has_direct_child_kind, identifier_name, named_children,
    nearest_ancestor_kind, Definition, DefinitionKind, Import, ImportKind, LanguageInfo,
    LanguageParser, LanguageRegistry, QueryKind, QuerySpec, SyntaxTree,
};
use codehealth_symbols::{
    populate_structural_fingerprints, Attribute, Definition as SymbolDefinition,
    DefinitionKind as SymbolDefinitionKind, FileSymbols, Import as SymbolImport, Language,
    Parameter, ReturnType, Signature, SymbolExtractor, SymbolRegistry, Visibility,
};
use tree_sitter::Node;

pub const QUERY_VERSION: u32 = 1;
const DEFINITIONS_QUERY: &str = include_str!("queries/definitions.scm");
const IMPORTS_QUERY: &str = include_str!("queries/imports.scm");

#[derive(Debug, Clone, Copy, Default)]
pub struct RustAdapter;

impl LanguageParser for RustAdapter {
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

    fn query_source(&self, kind: QueryKind) -> Option<QuerySpec> {
        Some(QuerySpec {
            kind,
            version: QUERY_VERSION,
            source: match kind {
                QueryKind::Definitions => DEFINITIONS_QUERY,
                QueryKind::Imports => IMPORTS_QUERY,
            },
        })
    }

    fn extract_definitions(&self, tree: &SyntaxTree) -> Vec<Definition> {
        let mut definitions = Vec::new();
        collect_definitions(tree.root_node(), tree, &mut definitions);
        definitions.sort_by(|left, right| left.span.start.cmp(&right.span.start));
        definitions
    }

    fn extract_imports(&self, tree: &SyntaxTree) -> Vec<Import> {
        let mut imports = Vec::new();
        collect_imports(tree.root_node(), tree, &mut imports);
        imports.sort_by(|left, right| left.span.start.cmp(&right.span.start));
        imports
    }
}

pub fn register(registry: &mut LanguageRegistry) {
    registry.register(RustAdapter);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RustSymbolExtractor;

impl SymbolExtractor for RustSymbolExtractor {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn extract(&self, tree: &SyntaxTree) -> FileSymbols {
        extract_symbols(tree)
    }
}

pub fn register_symbols(registry: &mut SymbolRegistry) {
    registry.register(RustSymbolExtractor);
}

fn extract_symbols(tree: &SyntaxTree) -> FileSymbols {
    let mut symbols = FileSymbols {
        path: tree.source.path.clone(),
        definitions: extract_definitions_from_tree(tree)
            .into_iter()
            .map(|definition| symbol_from_parser_definition(tree, definition))
            .collect(),
        imports: extract_imports_from_tree(tree)
            .into_iter()
            .map(symbol_import_from_parser_import)
            .collect(),
        exports: Vec::new(),
        call_sites: Vec::new(),
        references: Vec::new(),
    };
    collect_rust_items(tree.root_node(), tree, &mut symbols.definitions);
    symbols.definitions.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
    });
    symbols
}

fn extract_definitions_from_tree(tree: &SyntaxTree) -> Vec<Definition> {
    let mut definitions = Vec::new();
    collect_definitions(tree.root_node(), tree, &mut definitions);
    definitions.sort_by(|left, right| left.span.start.cmp(&right.span.start));
    definitions
}

fn extract_imports_from_tree(tree: &SyntaxTree) -> Vec<Import> {
    let mut imports = Vec::new();
    collect_imports(tree.root_node(), tree, &mut imports);
    imports.sort_by(|left, right| left.span.start.cmp(&right.span.start));
    imports
}

fn symbol_from_parser_definition(tree: &SyntaxTree, definition: Definition) -> SymbolDefinition {
    let kind = match definition.kind {
        DefinitionKind::ImplMethod => SymbolDefinitionKind::Method,
        DefinitionKind::TraitMethod => SymbolDefinitionKind::Method,
        _ => SymbolDefinitionKind::Function,
    };
    let name = definition.name.clone();
    let qualified_name = definition
        .parent
        .as_ref()
        .map(|parent| format!("{parent}.{name}"))
        .unwrap_or_else(|| name.clone());
    let mut symbol = SymbolDefinition::new(
        Language::Rust,
        kind,
        name,
        qualified_name,
        definition.path,
        definition.span,
    );
    symbol.body_span = definition.body_span;
    symbol.signature_span = definition.body_span.map_or(Some(definition.span), |body| {
        Some(codehealth_parser::Span {
            start: definition.span.start,
            end: body.start,
            start_position: definition.span.start_position,
            end_position: body.start_position,
        })
    });
    symbol.visibility = if definition.kind == DefinitionKind::TraitMethod {
        Visibility::Public
    } else {
        visibility_from_text(&tree.snippet(definition.span, 256))
    };
    symbol.is_exported = symbol.visibility != Visibility::Private;
    symbol.is_async = definition.is_async;
    symbol.signature = parse_rust_signature(&tree.snippet(symbol.signature_span.unwrap(), 512));
    symbol.attributes = attributes_before_span(tree, definition.span);
    populate_structural_fingerprints(tree, &mut symbol);
    symbol
}

fn symbol_import_from_parser_import(import: Import) -> SymbolImport {
    SymbolImport {
        language: Language::Rust,
        file: import.path,
        module: import.module,
        imported_names: import.imported_names,
        span: import.span,
    }
}

fn collect_rust_items(node: Node<'_>, tree: &SyntaxTree, definitions: &mut Vec<SymbolDefinition>) {
    let kind = match node.kind() {
        "struct_item" => Some(SymbolDefinitionKind::RustStruct),
        "enum_item" => Some(SymbolDefinitionKind::RustEnum),
        "trait_item" => Some(SymbolDefinitionKind::RustTrait),
        "impl_item" => Some(SymbolDefinitionKind::RustImpl),
        "mod_item" => Some(SymbolDefinitionKind::RustModule),
        _ => None,
    };
    if let Some(kind) = kind {
        let name = if node.kind() == "impl_item" {
            impl_parent_name(tree.text_for_node(node))
                .map(|target| format!("impl {target}"))
                .unwrap_or_else(|| "impl".to_string())
        } else {
            child_by_field_name(node, "name")
                .map(|name| tree.text_for_node(name).to_string())
                .unwrap_or_else(|| {
                    tree.text_for_node(node)
                        .lines()
                        .next()
                        .unwrap_or(node.kind())
                        .to_string()
                })
        };
        let mut symbol = SymbolDefinition::new(
            Language::Rust,
            kind,
            name.clone(),
            name,
            tree.source.path.clone(),
            tree.span_for_node(node),
        );
        symbol.body_span = child_by_field_name(node, "body").map(|body| tree.span_for_node(body));
        symbol.signature_span =
            Some(
                symbol
                    .body_span
                    .map_or(symbol.span, |body| codehealth_parser::Span {
                        start: symbol.span.start,
                        end: body.start,
                        start_position: symbol.span.start_position,
                        end_position: body.start_position,
                    }),
            );
        symbol.visibility = visibility_from_text(&tree.snippet(symbol.span, 256));
        symbol.is_exported = symbol.visibility != Visibility::Private;
        symbol.attributes = attributes_before_span(tree, symbol.span);
        definitions.push(symbol);
    }

    for child in named_children(node) {
        collect_rust_items(child, tree, definitions);
    }
}

fn collect_definitions(node: Node<'_>, tree: &SyntaxTree, definitions: &mut Vec<Definition>) {
    if node.kind() == "function_item" {
        if let Some((name, name_span)) = identifier_name(tree, child_by_field_name(node, "name")) {
            let ancestor = nearest_ancestor_kind(node, &["impl_item", "trait_item"]);
            let kind = match ancestor.map(|ancestor| ancestor.kind()) {
                Some("impl_item") => DefinitionKind::ImplMethod,
                Some("trait_item") => DefinitionKind::TraitMethod,
                _ => DefinitionKind::Function,
            };
            definitions.push(Definition {
                name,
                kind,
                language: tree.source.language.name.to_string(),
                path: tree.source.path.clone(),
                span: tree.span_for_node(node),
                name_span: Some(name_span),
                body_span: child_by_field_name(node, "body").map(|body| tree.span_for_node(body)),
                exported: has_direct_child_kind(node, "visibility_modifier"),
                is_async: tree
                    .text_for_node(node)
                    .trim_start()
                    .starts_with("async fn "),
                parent: ancestor.and_then(|ancestor| rust_parent_name(tree, ancestor)),
            });
        }
    }

    for child in named_children(node) {
        collect_definitions(child, tree, definitions);
    }
}

fn collect_imports(node: Node<'_>, tree: &SyntaxTree, imports: &mut Vec<Import>) {
    if node.kind() == "use_declaration" {
        imports.push(Import {
            module: tree.text_for_node(node).trim().to_string(),
            imported_names: Vec::new(),
            kind: ImportKind::RustUse,
            language: tree.source.language.name.to_string(),
            path: tree.source.path.clone(),
            span: tree.span_for_node(node),
        });
    }

    for child in named_children(node) {
        collect_imports(child, tree, imports);
    }
}

fn visibility_from_text(text: &str) -> Visibility {
    let trimmed = text.trim_start();
    if trimmed.starts_with("pub(crate)") {
        Visibility::Crate
    } else if trimmed.starts_with("pub(super)") {
        Visibility::Super
    } else if trimmed.starts_with("pub(") {
        let module = trimmed
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')').map(|(module, _)| module))
            .unwrap_or_default()
            .to_string();
        Visibility::Module(module)
    } else if trimmed.starts_with("pub ") || trimmed.starts_with("pub\n") {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

fn rust_parent_name(tree: &SyntaxTree, ancestor: Node<'_>) -> Option<String> {
    match ancestor.kind() {
        "trait_item" => child_by_field_name(ancestor, "name")
            .map(|name| tree.text_for_node(name).trim().to_string()),
        "impl_item" => impl_parent_name(tree.text_for_node(ancestor)),
        _ => None,
    }
}

fn impl_parent_name(text: &str) -> Option<String> {
    let header = text.split('{').next()?.trim();
    let header = header.strip_prefix("impl")?.trim();
    if header.is_empty() {
        return None;
    }

    let after_generics = if header.starts_with('<') {
        header
            .split_once('>')
            .map(|(_, rest)| rest.trim())
            .unwrap_or(header)
    } else {
        header
    };
    let target = after_generics
        .split_once(" for ")
        .map(|(_, target)| target.trim())
        .unwrap_or(after_generics);
    Some(
        collapse_whitespace(target)
            .trim_end_matches(';')
            .to_string(),
    )
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_rust_signature(text: &str) -> Signature {
    let generic_parameters = extract_between(text, '<', '>')
        .map(|value| split_list(&value))
        .unwrap_or_default();
    let parameters = extract_between(text, '(', ')')
        .map(|params| {
            split_list(&params)
                .into_iter()
                .filter_map(|raw| {
                    let raw = raw.trim().to_string();
                    if raw.is_empty() {
                        return None;
                    }
                    let (name, annotation) = raw
                        .split_once(':')
                        .map(|(left, right)| {
                            (left.trim().to_string(), Some(right.trim().to_string()))
                        })
                        .unwrap_or((raw, None));
                    Some(Parameter {
                        name,
                        type_annotation: annotation,
                        default_value: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let return_type = text.split("->").nth(1).map(|value| ReturnType {
        text: value
            .split(['{', ';'])
            .next()
            .unwrap_or(value)
            .trim()
            .to_string(),
    });

    Signature {
        generic_parameters,
        parameters,
        return_type,
    }
}

fn attributes_before_span(tree: &SyntaxTree, span: codehealth_parser::Span) -> Vec<Attribute> {
    let prefix = &tree.source.source[..span.start.min(tree.source.source.len())];
    let mut attributes = Vec::new();
    let mut offset = span.start;
    for line in prefix.lines().rev() {
        offset = offset.saturating_sub(line.len() + 1);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with("#[") {
            break;
        }
        let raw = trimmed.trim_start_matches("#[").trim_end_matches(']');
        attributes.push(Attribute {
            name: raw.split(['(', ' ']).next().unwrap_or(raw).to_string(),
            arguments: extract_between(raw, '(', ')'),
            span: codehealth_parser::span_for_offsets(
                &tree.source.source,
                offset + line.find("#[").unwrap_or(0),
                offset + line.len(),
            ),
        });
    }
    attributes.reverse();
    attributes
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

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_parser::{run_query, SourceFile};
    use std::path::Path;

    #[test]
    fn extracts_rust_definitions() {
        let parser = RustAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/rust/definitions.rs");
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
        assert!(definitions.iter().any(|definition| {
            definition.name == "save" && definition.kind == DefinitionKind::ImplMethod
        }));
        assert!(definitions.iter().any(|definition| {
            definition.name == "load" && definition.kind == DefinitionKind::TraitMethod
        }));
        assert!(!query_matches.is_empty());
        assert!(!tree.has_error());
    }

    #[test]
    fn snapshots_rust_symbols() {
        let parser = RustAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/rust/definitions.rs");
        let source = std::fs::read_to_string(&path).expect("fixture");
        let source_file = SourceFile::new(path, parser.info(), source);
        let tree = parser.parse(&source_file).expect("parse");

        insta::assert_snapshot!(codehealth_symbols::render_symbols_snapshot(&extract_symbols(&tree)), @r"
rust function add [pub]
rust function identity [pub]
rust function fetch_value [pub]
rust rust_trait Loader [pub]
rust method Loader.load [pub]
rust rust_struct Repository [pub]
rust rust_impl impl Repository [private]
rust method Repository.save [pub]
rust function macro_heavy [pub]
import rust use std::fmt::Debug;
");
    }
}
