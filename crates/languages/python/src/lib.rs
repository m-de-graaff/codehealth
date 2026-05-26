use codehealth_parser::{
    child_by_field_name, has_ancestor_kind, identifier_name, named_children, Definition,
    DefinitionKind, Import, ImportKind, LanguageInfo, LanguageParser, LanguageRegistry, QueryKind,
    QuerySpec, SyntaxTree,
};
use codehealth_symbols::{
    Decorator, Definition as SymbolDefinition, DefinitionKind as SymbolDefinitionKind,
    FastApiRouteMetadata, FileSymbols, FrameworkTag, Import as SymbolImport, Language, Parameter,
    ReturnType, Signature, SymbolExtractor, SymbolRegistry, Visibility,
};
use tree_sitter::Node;

pub const QUERY_VERSION: u32 = 1;
const DEFINITIONS_QUERY: &str = include_str!("queries/definitions.scm");
const IMPORTS_QUERY: &str = include_str!("queries/imports.scm");

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonAdapter;

impl LanguageParser for PythonAdapter {
    fn info(&self) -> LanguageInfo {
        LanguageInfo {
            name: "python",
            extensions: &["py", "pyi"],
            tree_sitter_grammar: "tree-sitter-python",
        }
    }

    fn tree_sitter_language(&self) -> Option<tree_sitter::Language> {
        Some(tree_sitter_python::LANGUAGE.into())
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
        collect_definitions(tree.root_node(), tree, &mut definitions, None);
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
    registry.register(PythonAdapter);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonSymbolExtractor;

impl SymbolExtractor for PythonSymbolExtractor {
    fn language(&self) -> Language {
        Language::Python
    }

    fn extract(&self, tree: &SyntaxTree) -> FileSymbols {
        extract_symbols(tree)
    }
}

pub fn register_symbols(registry: &mut SymbolRegistry) {
    registry.register(PythonSymbolExtractor);
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
    symbols.definitions.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
    });
    symbols
}

fn extract_definitions_from_tree(tree: &SyntaxTree) -> Vec<Definition> {
    let mut definitions = Vec::new();
    collect_definitions(tree.root_node(), tree, &mut definitions, None);
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
    let text = tree.snippet(definition.span, 4096);
    let decorators = decorators_for_definition(tree, definition.span);
    let route = decorators.iter().find_map(route_from_decorator);
    let is_pydantic = definition.kind == DefinitionKind::Class
        && (text.contains("(BaseModel)") || text.contains("pydantic"));
    let has_dependency = text.contains("Depends(");
    let kind = if route.is_some() {
        SymbolDefinitionKind::FastApiRoute
    } else if is_pydantic {
        SymbolDefinitionKind::PydanticModel
    } else if has_dependency && definition.kind == DefinitionKind::Function {
        SymbolDefinitionKind::FastApiDependency
    } else {
        match definition.kind {
            DefinitionKind::Class => SymbolDefinitionKind::Class,
            DefinitionKind::Method => SymbolDefinitionKind::Method,
            _ => SymbolDefinitionKind::Function,
        }
    };
    let qualified_name = definition
        .parent
        .as_ref()
        .map(|parent| format!("{parent}.{}", definition.name))
        .unwrap_or_else(|| definition.name.clone());
    let signature_span =
        definition
            .body_span
            .map_or(definition.span, |body| codehealth_parser::Span {
                start: definition.span.start,
                end: body.start,
                start_position: definition.span.start_position,
                end_position: body.start_position,
            });
    let mut symbol = SymbolDefinition::new(
        Language::Python,
        kind,
        definition.name,
        qualified_name,
        definition.path,
        definition.span,
    );
    symbol.body_span = definition.body_span;
    symbol.signature_span = Some(signature_span);
    symbol.decorators = decorators;
    symbol.visibility = Visibility::Private;
    symbol.is_async = definition.is_async;
    symbol.signature = parse_python_signature(&tree.snippet(signature_span, 1024));
    if let Some(route) = route {
        symbol
            .framework_tags
            .push(FrameworkTag::FastApiRoute(route));
    }
    if has_dependency {
        symbol.framework_tags.push(FrameworkTag::FastApiDependency);
    }
    if is_pydantic {
        symbol.framework_tags.push(FrameworkTag::PydanticModel);
    }
    symbol
}

fn symbol_import_from_parser_import(import: Import) -> SymbolImport {
    SymbolImport {
        language: Language::Python,
        file: import.path,
        module: import.module,
        imported_names: import.imported_names,
        span: import.span,
    }
}

fn collect_definitions(
    node: Node<'_>,
    tree: &SyntaxTree,
    definitions: &mut Vec<Definition>,
    parent: Option<String>,
) {
    match node.kind() {
        "class_definition" => {
            if let Some((name, name_span)) =
                identifier_name(tree, child_by_field_name(node, "name"))
            {
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
                    collect_definitions(child, tree, definitions, Some(name.clone()));
                }
                return;
            }
        }
        "function_definition" => {
            if let Some((name, name_span)) =
                identifier_name(tree, child_by_field_name(node, "name"))
            {
                let kind = if is_method(node) {
                    DefinitionKind::Method
                } else {
                    DefinitionKind::Function
                };
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
                    collect_definitions(child, tree, definitions, Some(name.clone()));
                }
                return;
            }
        }
        _ => {}
    }

    for child in named_children(node) {
        collect_definitions(child, tree, definitions, parent.clone());
    }
}

fn decorators_for_definition(tree: &SyntaxTree, span: codehealth_parser::Span) -> Vec<Decorator> {
    let prefix = &tree.source.source[..span.start.min(tree.source.source.len())];
    let mut decorators = Vec::new();
    let mut offset = span.start;
    for line in prefix.lines().rev() {
        offset = offset.saturating_sub(line.len() + 1);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with('@') {
            break;
        }
        let raw = trimmed.trim_start_matches('@');
        let name = raw.split(['(', ' ']).next().unwrap_or(raw).to_string();
        let arguments = raw
            .find('(')
            .and_then(|start| raw.rfind(')').map(|end| raw[start + 1..end].to_string()));
        decorators.push(Decorator {
            name,
            arguments,
            span: codehealth_parser::span_for_offsets(
                &tree.source.source,
                offset + line.find('@').unwrap_or(0),
                offset + line.len(),
            ),
        });
    }
    decorators.reverse();
    decorators
}

fn route_from_decorator(decorator: &Decorator) -> Option<FastApiRouteMetadata> {
    let (owner, method) = decorator.name.split_once('.')?;
    if !matches!(owner, "app" | "router") {
        return None;
    }
    let method = method.to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return None;
    }
    let arguments = decorator.arguments.as_deref().unwrap_or_default();
    Some(FastApiRouteMetadata {
        method,
        path: first_string_literal(arguments).unwrap_or_else(|| "/".to_string()),
        status_code: named_argument(arguments, "status_code"),
        response_model: named_argument(arguments, "response_model"),
        dependencies: named_argument(arguments, "dependencies")
            .into_iter()
            .collect(),
        tags: named_argument(arguments, "tags").into_iter().collect(),
        summary: named_string_argument(arguments, "summary"),
        description: named_string_argument(arguments, "description"),
    })
}

fn parse_python_signature(text: &str) -> Signature {
    let parameters = extract_between(text, '(', ')')
        .map(|params| {
            params
                .split(',')
                .filter_map(|raw| {
                    let raw = raw.trim();
                    if raw.is_empty() {
                        return None;
                    }
                    let (name_part, default_value) = raw
                        .split_once('=')
                        .map(|(left, right)| (left.trim(), Some(right.trim().to_string())))
                        .unwrap_or((raw, None));
                    let (name, type_annotation) = name_part
                        .split_once(':')
                        .map(|(left, right)| (left.trim(), Some(right.trim().to_string())))
                        .unwrap_or((name_part, None));
                    Some(Parameter {
                        name: name.to_string(),
                        type_annotation,
                        default_value,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let return_type = text.split("->").nth(1).map(|value| ReturnType {
        text: value.split(':').next().unwrap_or(value).trim().to_string(),
    });

    Signature {
        parameters,
        return_type,
        ..Signature::default()
    }
}

fn extract_between(text: &str, start: char, end: char) -> Option<String> {
    let start_index = text.find(start)?;
    let rest = &text[start_index + start.len_utf8()..];
    let end_index = rest.find(end)?;
    Some(rest[..end_index].trim().to_string())
}

fn first_string_literal(text: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let Some(start) = text.find(quote) else {
            continue;
        };
        let rest = &text[start + 1..];
        let Some(end) = rest.find(quote) else {
            continue;
        };
        return Some(rest[..end].to_string());
    }
    None
}

fn named_argument(text: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=");
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    Some(rest.split(',').next().unwrap_or(rest).trim().to_string())
}

fn named_string_argument(text: &str, name: &str) -> Option<String> {
    named_argument(text, name).map(|value| value.trim_matches(['"', '\'']).to_string())
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
        exported: false,
        is_async: tree
            .text_for_node(node)
            .trim_start()
            .starts_with("async def "),
        parent,
    }
}

fn is_method(node: Node<'_>) -> bool {
    has_ancestor_kind(node, "class_definition")
}

fn collect_imports(node: Node<'_>, tree: &SyntaxTree, imports: &mut Vec<Import>) {
    match node.kind() {
        "import_statement" => imports.push(Import {
            module: tree
                .text_for_node(node)
                .trim_start_matches("import ")
                .to_string(),
            imported_names: Vec::new(),
            kind: ImportKind::PythonImport,
            language: tree.source.language.name.to_string(),
            path: tree.source.path.clone(),
            span: tree.span_for_node(node),
        }),
        "import_from_statement" => imports.push(Import {
            module: tree.text_for_node(node).to_string(),
            imported_names: Vec::new(),
            kind: ImportKind::PythonFrom,
            language: tree.source.language.name.to_string(),
            path: tree.source.path.clone(),
            span: tree.span_for_node(node),
        }),
        _ => {}
    }

    for child in named_children(node) {
        collect_imports(child, tree, imports);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codehealth_parser::{run_query, SourceFile};
    use std::path::Path;

    #[test]
    fn extracts_python_definitions() {
        let parser = PythonAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures/parser/python/definitions.py");
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
            .any(|definition| definition.name == "load_user"));
        assert!(definitions.iter().any(|definition| {
            definition.name == "save" && definition.kind == DefinitionKind::Method
        }));
        assert!(!query_matches.is_empty());
        assert!(!tree.has_error());
    }

    #[test]
    fn snapshots_fastapi_symbols() {
        let parser = PythonAdapter;
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/fastapi/app.py");
        let source = std::fs::read_to_string(&path).expect("fixture");
        let source_file = SourceFile::new(path, parser.info(), source);
        let tree = parser.parse(&source_file).expect("parse");

        insta::assert_snapshot!(codehealth_symbols::render_symbols_snapshot(&extract_symbols(&tree)), @r"
python fastapi_route health [private]
import python from fastapi import FastAPI
");
    }
}
