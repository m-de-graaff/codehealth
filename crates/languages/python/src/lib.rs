use codehealth_parser::{
    child_by_field_name, has_ancestor_kind, identifier_name, named_children, Definition,
    DefinitionKind, Import, ImportKind, LanguageInfo, LanguageParser, LanguageRegistry, QueryKind,
    QuerySpec, SyntaxTree,
};
use codehealth_symbols::{
    populate_structural_fingerprints, CallSite, Decorator, Definition as SymbolDefinition,
    DefinitionKind as SymbolDefinitionKind, FastApiRouteMetadata, FileSymbols, FrameworkTag,
    Import as SymbolImport, Language, Parameter, ReturnType, Signature, SymbolExtractor,
    SymbolRegistry, Visibility,
};
use std::collections::{BTreeMap, BTreeSet};
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
    let fastapi = FastApiFileContext::from_tree(tree);
    let mut symbols = FileSymbols {
        path: tree.source.path.clone(),
        definitions: extract_definitions_from_tree(tree)
            .into_iter()
            .map(|definition| symbol_from_parser_definition(tree, definition, &fastapi))
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
    collect_call_sites(tree.root_node(), tree, &mut symbols.call_sites);
    symbols.call_sites.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.span.start.cmp(&right.span.start))
            .then_with(|| left.callee.cmp(&right.callee))
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

fn symbol_from_parser_definition(
    tree: &SyntaxTree,
    definition: Definition,
    fastapi: &FastApiFileContext,
) -> SymbolDefinition {
    let text = tree.snippet(definition.span, 4096);
    let decorators = decorators_for_definition(tree, definition.span);
    let mut route = decorators
        .iter()
        .find_map(|decorator| route_from_decorator(decorator, fastapi));
    let is_pydantic = definition.kind == DefinitionKind::Class
        && (text.contains("BaseModel") || text.contains("pydantic"));
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
    if let Some(route) = route.as_mut() {
        let dependency_defaults = dependency_defaults(&symbol.signature);
        for dependency in &dependency_defaults {
            if !route.dependencies.contains(dependency) {
                route.dependencies.push(dependency.clone());
            }
        }
        route.auth_dependency = security_dependency(&symbol.signature)
            .or_else(|| security_dependency_from_source(&text))
            .or_else(|| route.auth_dependency.clone());
    }
    if let Some(route) = route {
        symbol
            .framework_tags
            .push(FrameworkTag::FastApiRoute(Box::new(route)));
    }
    if has_dependency {
        symbol.framework_tags.push(FrameworkTag::FastApiDependency);
    }
    if is_pydantic {
        symbol.framework_tags.push(FrameworkTag::PydanticModel);
    }
    populate_structural_fingerprints(tree, &mut symbol);
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

#[derive(Debug, Default)]
struct FastApiFileContext {
    app_variables: BTreeSet<String>,
    router_prefixes: BTreeMap<String, String>,
    router_include_prefixes: BTreeMap<String, String>,
}

impl FastApiFileContext {
    fn from_tree(tree: &SyntaxTree) -> Self {
        let mut context = Self::default();
        for line in tree.source.source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some((name, rest)) = trimmed.split_once('=') {
                let name = name.trim();
                let rest = rest.trim();
                if is_identifier(name) && rest.starts_with("FastAPI(") {
                    context.app_variables.insert(name.to_string());
                }
                if is_identifier(name) && rest.starts_with("APIRouter(") {
                    let prefix = extract_between(rest, '(', ')')
                        .and_then(|arguments| named_string_argument(&arguments, "prefix"))
                        .unwrap_or_default();
                    context.router_prefixes.insert(name.to_string(), prefix);
                }
            }
            if let Some(arguments) = include_router_arguments(trimmed) {
                let router = arguments
                    .split(',')
                    .next()
                    .map(str::trim)
                    .unwrap_or_default();
                if is_identifier(router) {
                    let prefix = named_string_argument(arguments, "prefix").unwrap_or_default();
                    context
                        .router_include_prefixes
                        .insert(router.to_string(), prefix);
                }
            }
        }

        context.app_variables.insert("app".to_string());
        context
            .router_prefixes
            .entry("router".to_string())
            .or_default();
        context
    }
}

fn route_from_decorator(
    decorator: &Decorator,
    fastapi: &FastApiFileContext,
) -> Option<FastApiRouteMetadata> {
    let (owner, method) = decorator.name.split_once('.')?;
    if !fastapi.app_variables.contains(owner) && !fastapi.router_prefixes.contains_key(owner) {
        return None;
    }
    let method = method.to_ascii_uppercase();
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return None;
    }
    let arguments = decorator.arguments.as_deref().unwrap_or_default();
    let raw_path = first_string_literal(arguments).unwrap_or_else(|| "/".to_string());
    let router_prefix = fastapi
        .router_prefixes
        .get(owner)
        .filter(|prefix| !prefix.is_empty())
        .cloned();
    let include_prefix = fastapi
        .router_include_prefixes
        .get(owner)
        .filter(|prefix| !prefix.is_empty())
        .cloned();
    let resolved_path = join_paths([
        include_prefix.as_deref(),
        router_prefix.as_deref(),
        Some(raw_path.as_str()),
    ]);
    Some(FastApiRouteMetadata {
        method,
        path: resolved_path,
        raw_path: Some(raw_path),
        router_variable: Some(owner.to_string()),
        router_prefix,
        include_prefix,
        status_code: named_argument(arguments, "status_code"),
        response_model: named_argument(arguments, "response_model"),
        dependencies: dependency_calls(arguments),
        tags: list_string_argument(arguments, "tags"),
        summary: named_string_argument(arguments, "summary"),
        description: named_string_argument(arguments, "description"),
        auth_dependency: security_dependency_from_source(arguments),
    })
}

fn collect_call_sites(node: Node<'_>, tree: &SyntaxTree, calls: &mut Vec<CallSite>) {
    if node.kind() == "call" {
        if let Some(function) =
            child_by_field_name(node, "function").or_else(|| node.named_child(0))
        {
            calls.push(CallSite {
                language: Language::Python,
                file: tree.source.path.clone(),
                callee: tree.text_for_node(function).to_string(),
                span: tree.span_for_node(node),
            });
        }
    }

    for child in named_children(node) {
        collect_call_sites(child, tree, calls);
    }
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

fn list_string_argument(text: &str, name: &str) -> Vec<String> {
    named_argument(text, name)
        .map(|value| {
            value
                .trim_matches(['[', ']'])
                .split(',')
                .map(|part| part.trim().trim_matches(['"', '\'']))
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn dependency_defaults(signature: &Signature) -> Vec<String> {
    let mut dependencies = Vec::new();
    for parameter in &signature.parameters {
        if let Some(default) = &parameter.default_value {
            if default.contains("Depends(") || default.contains("Security(") {
                dependencies.push(call_argument(default).unwrap_or_else(|| default.clone()));
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn dependency_calls(text: &str) -> Vec<String> {
    let mut dependencies = Vec::new();
    for marker in ["Depends(", "Security("] {
        for (index, _) in text.match_indices(marker) {
            let start = index + marker.len();
            let raw = text[start..]
                .split(')')
                .next()
                .unwrap_or_default()
                .split(',')
                .next()
                .unwrap_or_default()
                .trim();
            if !raw.is_empty() {
                dependencies.push(raw.to_string());
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn security_dependency(signature: &Signature) -> Option<String> {
    signature.parameters.iter().find_map(|parameter| {
        parameter.default_value.as_deref().and_then(|default| {
            if default.contains("Security(")
                || default.contains("OAuth2")
                || default.contains("APIKey")
                || default.contains("HTTPBearer")
            {
                call_argument(default).or_else(|| Some(default.to_string()))
            } else {
                None
            }
        })
    })
}

fn security_dependency_from_source(text: &str) -> Option<String> {
    for marker in ["Security(", "OAuth2", "APIKey", "HTTPBearer", "HTTPBasic"] {
        if let Some(index) = text.find(marker) {
            let rest = &text[index..];
            return Some(
                rest.split([',', ')', ']'])
                    .next()
                    .unwrap_or(marker)
                    .trim()
                    .to_string(),
            );
        }
    }
    None
}

fn call_argument(text: &str) -> Option<String> {
    let start = text.find('(')? + 1;
    let rest = &text[start..];
    let argument = rest
        .split(')')
        .next()
        .unwrap_or_default()
        .split(',')
        .next()
        .unwrap_or_default()
        .trim();
    (!argument.is_empty()).then(|| argument.to_string())
}

fn include_router_arguments(text: &str) -> Option<&str> {
    let marker = ".include_router(";
    let start = text.find(marker)? + marker.len();
    let rest = &text[start..];
    let end = rest.rfind(')').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn join_paths<'a>(parts: impl IntoIterator<Item = Option<&'a str>>) -> String {
    let mut output = String::new();
    for part in parts.into_iter().flatten() {
        let part = part.trim();
        if part.is_empty() || part == "/" {
            continue;
        }
        if !output.ends_with('/') {
            output.push('/');
        }
        output.push_str(part.trim_matches('/'));
    }
    if output.is_empty() {
        "/".to_string()
    } else {
        output
    }
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
