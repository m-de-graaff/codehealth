use codehealth_core::{
    AutofixSafety, Confidence, Finding, FindingKind, FindingLocation, Location, Severity,
    SourceSpan,
};
use codehealth_parser::{LanguageInfo, LanguageRegistry, SourceFile, Span, SyntaxTree};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

mod canonical;

pub use canonical::*;

pub const DUPLICATE_NAME_FUNCTION_RULE: &str = "duplicate.name.function";
pub const DUPLICATE_NAME_RULE: &str = DUPLICATE_NAME_FUNCTION_RULE;
pub const DUPLICATE_NAME_CLASS_RULE: &str = "duplicate.name.class";
pub const DUPLICATE_NAME_METHOD_RULE: &str = "duplicate.name.method";
pub const DUPLICATE_NAME_REACT_COMPONENT_RULE: &str = "duplicate.name.react_component";
pub const DUPLICATE_NAME_REACT_HOOK_RULE: &str = "duplicate.name.react_hook";
pub const DUPLICATE_NAME_FASTAPI_ROUTE_HANDLER_RULE: &str = "duplicate.name.fastapi_route_handler";
pub const DUPLICATE_NAME_RUST_TYPE_RULE: &str = "duplicate.name.rust_type";
pub const DUPLICATE_NAME_RUST_IMPL_METHOD_RULE: &str = "duplicate.name.rust_impl_method";
pub const FASTAPI_DUPLICATE_ROUTE_RULE: &str = "fastapi.duplicate.route";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    TypeScript,
    Tsx,
    Python,
    Rust,
}

impl Language {
    pub fn from_info(info: LanguageInfo) -> Option<Self> {
        match info.name {
            "typescript" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "python" => Some(Self::Python),
            "rust" => Some(Self::Rust),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefinitionKind {
    Function,
    Method,
    Class,
    Interface,
    TypeAlias,
    ReactComponent,
    ReactHook,
    FastApiRoute,
    FastApiDependency,
    PydanticModel,
    RustStruct,
    RustEnum,
    RustTrait,
    RustImpl,
    RustModule,
}

impl DefinitionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::TypeAlias => "type_alias",
            Self::ReactComponent => "react_component",
            Self::ReactHook => "react_hook",
            Self::FastApiRoute => "fastapi_route",
            Self::FastApiDependency => "fastapi_dependency",
            Self::PydanticModel => "pydantic_model",
            Self::RustStruct => "rust_struct",
            Self::RustEnum => "rust_enum",
            Self::RustTrait => "rust_trait",
            Self::RustImpl => "rust_impl",
            Self::RustModule => "rust_module",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub id: DefinitionId,
    pub language: Language,
    pub kind: DefinitionKind,
    pub name: String,
    pub qualified_name: String,
    pub file: PathBuf,
    pub span: Span,
    pub body_span: Option<Span>,
    pub signature_span: Option<Span>,
    pub visibility: Visibility,
    pub is_async: bool,
    pub is_exported: bool,
    pub decorators: Vec<Decorator>,
    pub attributes: Vec<Attribute>,
    pub framework_tags: Vec<FrameworkTag>,
    pub signature: Signature,
    pub structural_fingerprint: Option<StructuralFingerprint>,
    pub literal_normalized_structural_fingerprint: Option<StructuralFingerprint>,
}

impl Definition {
    pub fn new(
        language: Language,
        kind: DefinitionKind,
        name: impl Into<String>,
        qualified_name: impl Into<String>,
        file: impl Into<PathBuf>,
        span: Span,
    ) -> Self {
        let name = name.into();
        let qualified_name = qualified_name.into();
        let file = file.into();
        let id = stable_definition_id(language, kind, &qualified_name, &file, span);
        Self {
            id,
            language,
            kind,
            name,
            qualified_name,
            file,
            span,
            body_span: None,
            signature_span: None,
            visibility: Visibility::Private,
            is_async: false,
            is_exported: false,
            decorators: Vec::new(),
            attributes: Vec::new(),
            framework_tags: Vec::new(),
            signature: Signature::default(),
            structural_fingerprint: None,
            literal_normalized_structural_fingerprint: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature {
    pub generic_parameters: Vec<String>,
    pub parameters: Vec<Parameter>,
    pub return_type: Option<ReturnType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: String,
    pub type_annotation: Option<String>,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnType {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
    Crate,
    Super,
    Module(String),
}

impl Visibility {
    pub fn label(&self) -> String {
        match self {
            Self::Private => "private".to_string(),
            Self::Public => "pub".to_string(),
            Self::Crate => "pub(crate)".to_string(),
            Self::Super => "pub(super)".to_string(),
            Self::Module(module) => format!("pub({module})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decorator {
    pub name: String,
    pub arguments: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub arguments: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameworkTag {
    ReactComponent,
    ReactHook,
    ReactMemo,
    ReactForwardRef,
    ReactStateHook,
    ReactEffectHook,
    ReactContextHook,
    ReactChildComponent(String),
    ReactJsxElement(String),
    FastApiRoute(FastApiRouteMetadata),
    FastApiDependency,
    PydanticModel,
}

impl FrameworkTag {
    pub fn label(&self) -> String {
        match self {
            Self::ReactComponent => "react.component".to_string(),
            Self::ReactHook => "react.hook".to_string(),
            Self::ReactMemo => "react.memo".to_string(),
            Self::ReactForwardRef => "react.forward_ref".to_string(),
            Self::ReactStateHook => "react.use_state".to_string(),
            Self::ReactEffectHook => "react.use_effect".to_string(),
            Self::ReactContextHook => "react.use_context".to_string(),
            Self::ReactChildComponent(name) => format!("react.child:{name}"),
            Self::ReactJsxElement(name) => format!("react.jsx:{name}"),
            Self::FastApiRoute(route) => format!("fastapi.route:{} {}", route.method, route.path),
            Self::FastApiDependency => "fastapi.dependency".to_string(),
            Self::PydanticModel => "pydantic.model".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FastApiRouteMetadata {
    pub method: String,
    pub path: String,
    pub status_code: Option<String>,
    pub response_model: Option<String>,
    pub dependencies: Vec<String>,
    pub tags: Vec<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub language: Language,
    pub file: PathBuf,
    pub module: String,
    pub imported_names: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub language: Language,
    pub file: PathBuf,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub language: Language,
    pub file: PathBuf,
    pub callee: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub language: Language,
    pub file: PathBuf,
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileSymbols {
    pub path: PathBuf,
    pub definitions: Vec<Definition>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub call_sites: Vec<CallSite>,
    pub references: Vec<Reference>,
}

pub trait SymbolExtractor: Send + Sync {
    fn language(&self) -> Language;
    fn extract(&self, tree: &SyntaxTree) -> FileSymbols;
}

#[derive(Default)]
pub struct SymbolRegistry {
    extractors: BTreeMap<Language, Box<dyn SymbolExtractor>>,
}

impl SymbolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<E>(&mut self, extractor: E)
    where
        E: SymbolExtractor + 'static,
    {
        self.extractors
            .insert(extractor.language(), Box::new(extractor));
    }

    pub fn extractor_for_language(&self, language: Language) -> Option<&dyn SymbolExtractor> {
        self.extractors.get(&language).map(Box::as_ref)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInput {
    pub path: PathBuf,
    pub language: LanguageInfo,
}

#[derive(Debug, Default)]
pub struct SymbolBuildResult {
    pub index: SymbolIndex,
    pub files_parsed: usize,
    pub parse_errors: usize,
}

pub fn build_symbol_index(
    inputs: &[SymbolInput],
    parser_registry: &LanguageRegistry,
    symbol_registry: &SymbolRegistry,
) -> SymbolBuildResult {
    let mut result = SymbolBuildResult::default();

    for input in inputs {
        let Some(language) = Language::from_info(input.language) else {
            result.parse_errors += 1;
            continue;
        };
        let Some(parser) = parser_registry.adapter_for_path(&input.path) else {
            result.parse_errors += 1;
            continue;
        };
        let Some(extractor) = symbol_registry.extractor_for_language(language) else {
            result.parse_errors += 1;
            continue;
        };
        let source = match SourceFile::from_path(&input.path, input.language) {
            Ok(source) => source,
            Err(_) => {
                result.parse_errors += 1;
                continue;
            }
        };
        let tree = match parser.parse(&source) {
            Ok(tree) => tree,
            Err(_) => {
                result.parse_errors += 1;
                continue;
            }
        };

        result.files_parsed += 1;
        if tree.has_error() {
            result.parse_errors += tree.diagnostics().len().max(1);
        }
        result.index.add_file_symbols(extractor.extract(&tree));
    }

    result.index.finalize();
    result
}

#[derive(Debug, Default)]
pub struct SymbolIndex {
    pub definitions: Vec<Definition>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub call_sites: Vec<CallSite>,
    pub references: Vec<Reference>,
    pub per_file: BTreeMap<PathBuf, Vec<DefinitionId>>,
    pub per_module: BTreeMap<String, Vec<DefinitionId>>,
    pub by_name: BTreeMap<String, Vec<DefinitionId>>,
    pub by_qualified_name: BTreeMap<String, DefinitionId>,
    pub by_kind: BTreeMap<DefinitionKind, Vec<DefinitionId>>,
    pub by_framework: BTreeMap<String, Vec<DefinitionId>>,
    pub route_index: BTreeMap<String, Vec<DefinitionId>>,
    pub component_index: BTreeMap<String, DefinitionId>,
    pub class_model_index: BTreeMap<String, DefinitionId>,
}

impl SymbolIndex {
    pub fn add_file_symbols(&mut self, symbols: FileSymbols) {
        self.imports.extend(symbols.imports);
        self.exports.extend(symbols.exports);
        self.call_sites.extend(symbols.call_sites);
        self.references.extend(symbols.references);
        self.definitions.extend(symbols.definitions);
    }

    pub fn finalize(&mut self) {
        self.definitions.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.start.cmp(&right.span.start))
                .then_with(|| left.qualified_name.cmp(&right.qualified_name))
        });
        self.imports.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.start.cmp(&right.span.start))
        });

        self.per_file.clear();
        self.per_module.clear();
        self.by_name.clear();
        self.by_qualified_name.clear();
        self.by_kind.clear();
        self.by_framework.clear();
        self.route_index.clear();
        self.component_index.clear();
        self.class_model_index.clear();

        for definition in &self.definitions {
            self.per_file
                .entry(definition.file.clone())
                .or_default()
                .push(definition.id.clone());
            self.per_module
                .entry(module_key(&definition.file))
                .or_default()
                .push(definition.id.clone());
            self.by_name
                .entry(definition.name.clone())
                .or_default()
                .push(definition.id.clone());
            self.by_qualified_name
                .insert(definition.qualified_name.clone(), definition.id.clone());
            self.by_kind
                .entry(definition.kind)
                .or_default()
                .push(definition.id.clone());

            if definition.kind == DefinitionKind::ReactComponent {
                self.component_index
                    .insert(definition.qualified_name.clone(), definition.id.clone());
            }
            if matches!(
                definition.kind,
                DefinitionKind::Class | DefinitionKind::PydanticModel
            ) {
                self.class_model_index
                    .insert(definition.qualified_name.clone(), definition.id.clone());
            }

            for tag in &definition.framework_tags {
                let label = tag.label();
                self.by_framework
                    .entry(label.clone())
                    .or_default()
                    .push(definition.id.clone());
                if let FrameworkTag::FastApiRoute(route) = tag {
                    self.route_index
                        .entry(format!("{} {}", route.method, route.path))
                        .or_default()
                        .push(definition.id.clone());
                }
            }
        }
    }

    pub fn definition_by_id(&self, id: &DefinitionId) -> Option<&Definition> {
        self.definitions
            .iter()
            .find(|definition| &definition.id == id)
    }
}

pub fn find_duplicate_name_findings(index: &SymbolIndex) -> Vec<Finding> {
    let mut groups: BTreeMap<(Language, &'static str, String), Vec<&Definition>> = BTreeMap::new();
    for definition in &index.definitions {
        if let Some(rule_id) = duplicate_name_rule_id(definition) {
            groups
                .entry((definition.language, rule_id, definition.name.clone()))
                .or_default()
                .push(definition);
        }
    }

    let mut findings = Vec::new();
    for ((language, rule_id, name), mut definitions) in groups {
        definitions.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.start.cmp(&right.span.start))
        });
        if definitions.len() < 2 {
            continue;
        }

        let Some(score) = duplicate_name_score(&definitions) else {
            continue;
        };
        findings.push(duplicate_name_finding(
            language,
            rule_id,
            &name,
            &definitions,
            score,
        ));
    }

    findings
}

pub fn find_duplicate_fastapi_route_findings(index: &SymbolIndex) -> Vec<Finding> {
    let mut groups: BTreeMap<String, Vec<&Definition>> = BTreeMap::new();
    for definition in &index.definitions {
        for tag in &definition.framework_tags {
            if let FrameworkTag::FastApiRoute(route) = tag {
                groups
                    .entry(format!("{} {}", route.method, route.path))
                    .or_default()
                    .push(definition);
            }
        }
    }

    let mut findings = Vec::new();
    for (route, mut definitions) in groups {
        if definitions.len() < 2 {
            continue;
        }
        definitions.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.start.cmp(&right.span.start))
        });
        findings.push(duplicate_fastapi_route_finding(&route, &definitions));
    }

    findings
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DuplicateNameScore {
    score: usize,
    scope: String,
    signals: Vec<String>,
    severity: Severity,
    confidence: Confidence,
}

fn duplicate_name_rule_id(definition: &Definition) -> Option<&'static str> {
    match definition.kind {
        DefinitionKind::Function => Some(DUPLICATE_NAME_FUNCTION_RULE),
        DefinitionKind::Class | DefinitionKind::PydanticModel => Some(DUPLICATE_NAME_CLASS_RULE),
        DefinitionKind::Method => {
            if definition.language == Language::Rust {
                Some(DUPLICATE_NAME_RUST_IMPL_METHOD_RULE)
            } else {
                Some(DUPLICATE_NAME_METHOD_RULE)
            }
        }
        DefinitionKind::ReactComponent => Some(DUPLICATE_NAME_REACT_COMPONENT_RULE),
        DefinitionKind::ReactHook => Some(DUPLICATE_NAME_REACT_HOOK_RULE),
        DefinitionKind::FastApiRoute => Some(DUPLICATE_NAME_FASTAPI_ROUTE_HANDLER_RULE),
        DefinitionKind::RustStruct | DefinitionKind::RustEnum | DefinitionKind::RustTrait => {
            Some(DUPLICATE_NAME_RUST_TYPE_RULE)
        }
        _ => None,
    }
}

fn duplicate_name_score(definitions: &[&Definition]) -> Option<DuplicateNameScore> {
    let mut score = 0;
    let mut signals = Vec::new();
    let scopes = definitions
        .iter()
        .map(|definition| scope_key(definition))
        .collect::<BTreeSet<_>>();
    let modules = definitions
        .iter()
        .map(|definition| module_key(&definition.file))
        .collect::<BTreeSet<_>>();
    let directories = definitions
        .iter()
        .map(|definition| directory_key(&definition.file))
        .collect::<BTreeSet<_>>();
    let owners = definitions
        .iter()
        .filter_map(|definition| owner_context(definition))
        .collect::<BTreeSet<_>>();
    let public_api_count = definitions
        .iter()
        .filter(|definition| {
            definition.is_exported || !matches!(definition.visibility, Visibility::Private)
        })
        .count();
    let framework_specific = definitions
        .iter()
        .any(|definition| framework_for_kind(definition.kind).is_some());
    let same_scope = scopes.len() == 1;
    let same_directory = directories.len() == 1;
    let similar_owner = owners_are_similar(&owners);
    let cross_module = modules.len() > 1;

    if same_scope {
        score += 5;
        signals.push("same_scope".to_string());
    }
    if same_directory {
        score += 2;
        signals.push("same_directory".to_string());
    }
    if cross_module {
        score += 1;
        signals.push("cross_module".to_string());
    }
    if framework_specific {
        score += 3;
        signals.push("framework_specific".to_string());
    }
    if public_api_count > 0 {
        score += public_api_count.min(3);
        signals.push("public_api".to_string());
    }
    if owners.len() == 1 && !owners.is_empty() {
        score += 3;
        signals.push("same_owner_context".to_string());
    } else if similar_owner {
        score += 2;
        signals.push("similar_owner_context".to_string());
    }

    let first = definitions.first()?;
    let common_method_name =
        first.kind == DefinitionKind::Method && common_method_name(&first.name);
    if common_method_name && !(same_scope || owners.len() == 1 || similar_owner) {
        return None;
    }

    if score < minimum_duplicate_name_score(first) {
        return None;
    }

    let (severity, confidence) =
        if same_scope || first.kind == DefinitionKind::FastApiRoute || score >= 7 {
            (Severity::High, Confidence::Certain)
        } else if score >= 4 {
            (Severity::Medium, Confidence::High)
        } else {
            (Severity::Low, Confidence::Medium)
        };

    Some(DuplicateNameScore {
        score,
        scope: if same_scope {
            "same_scope".to_string()
        } else if same_directory {
            "same_directory".to_string()
        } else {
            "cross_module".to_string()
        },
        signals,
        severity,
        confidence,
    })
}

fn minimum_duplicate_name_score(definition: &Definition) -> usize {
    match definition.kind {
        DefinitionKind::ReactComponent
        | DefinitionKind::ReactHook
        | DefinitionKind::FastApiRoute => 2,
        DefinitionKind::Method => 3,
        _ => 3,
    }
}

fn common_method_name(name: &str) -> bool {
    matches!(
        name,
        "new" | "from" | "to_string" | "render" | "map" | "filter" | "handleSubmit"
    )
}

fn duplicate_name_finding(
    language: Language,
    rule_id: &str,
    name: &str,
    definitions: &[&Definition],
    score: DuplicateNameScore,
) -> Finding {
    let paths = definitions
        .iter()
        .map(|definition| definition.file.to_string_lossy())
        .collect::<Vec<_>>()
        .join("|");
    let stable = stable_key(&format!("{rule_id}|{}|{name}|{paths}", language.label(),));
    let definition_kind = definitions
        .first()
        .map(|definition| definition.kind.label())
        .unwrap_or("symbol");
    let public_api_count = definitions
        .iter()
        .filter(|definition| {
            definition.is_exported || !matches!(definition.visibility, Visibility::Private)
        })
        .count();
    let qualified_names = definitions
        .iter()
        .map(|definition| definition.qualified_name.clone())
        .collect::<Vec<_>>();
    let mut metadata = BTreeMap::new();
    metadata.insert("scope".to_string(), serde_json::json!(score.scope));
    metadata.insert("score".to_string(), serde_json::json!(score.score));
    metadata.insert("signals".to_string(), serde_json::json!(score.signals));
    metadata.insert(
        "qualified_names".to_string(),
        serde_json::json!(qualified_names),
    );
    metadata.insert(
        "public_api_count".to_string(),
        serde_json::json!(public_api_count),
    );

    Finding {
        finding_id: format!("{}:{}", rule_id, &stable[..12]),
        baseline_key: stable,
        rule_id: rule_id.to_string(),
        kind: FindingKind::DuplicateName,
        severity: score.severity,
        confidence: score.confidence,
        message: format!(
            "{} {} definitions share the name '{}'.",
            definitions.len(),
            definition_kind,
            name
        ),
        locations: definitions
            .iter()
            .map(|definition| FindingLocation {
                path: definition.file.clone(),
                span: Some(SourceSpan {
                    start: definition.span.start,
                    end: definition.span.end,
                }),
                start: Some(Location {
                    line: definition.span.start_position.line,
                    column: definition.span.start_position.column,
                    byte_offset: definition.span.start,
                }),
                language: Some(definition.language.label().to_string()),
            })
            .collect(),
        language: Some(language.label().to_string()),
        framework: definitions
            .first()
            .and_then(|definition| framework_for_kind(definition.kind))
            .map(str::to_string),
        explanation: format!(
            "These {} definitions share the same symbol name in the indexed symbol table.",
            definition_kind
        ),
        remediation:
            "Rename one symbol, narrow its scope, or document why the duplicate name is intentional."
                .to_string(),
        detection_reason:
            "The symbol index grouped definitions by language, kind, and simple name.".to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "Renaming symbols is not auto-fixed because call sites, exports, and public APIs may need coordinated changes."
                .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn duplicate_fastapi_route_finding(route: &str, definitions: &[&Definition]) -> Finding {
    let paths = definitions
        .iter()
        .map(|definition| definition.file.to_string_lossy())
        .collect::<Vec<_>>()
        .join("|");
    let stable = stable_key(&format!("{FASTAPI_DUPLICATE_ROUTE_RULE}|{route}|{paths}"));
    let handler_names = definitions
        .iter()
        .map(|definition| definition.name.clone())
        .collect::<Vec<_>>();
    let mut metadata = BTreeMap::new();
    metadata.insert("route".to_string(), serde_json::json!(route));
    metadata.insert(
        "handler_names".to_string(),
        serde_json::json!(handler_names),
    );

    Finding {
        finding_id: format!("{}:{}", FASTAPI_DUPLICATE_ROUTE_RULE, &stable[..12]),
        baseline_key: stable,
        rule_id: FASTAPI_DUPLICATE_ROUTE_RULE.to_string(),
        kind: FindingKind::FastApi,
        severity: Severity::High,
        confidence: Confidence::Certain,
        message: format!(
            "{} FastAPI handlers register the same route '{}'.",
            definitions.len(),
            route
        ),
        locations: definitions
            .iter()
            .map(|definition| FindingLocation {
                path: definition.file.clone(),
                span: Some(SourceSpan {
                    start: definition.span.start,
                    end: definition.span.end,
                }),
                start: Some(Location {
                    line: definition.span.start_position.line,
                    column: definition.span.start_position.column,
                    byte_offset: definition.span.start,
                }),
                language: Some(definition.language.label().to_string()),
            })
            .collect(),
        language: Some("python".to_string()),
        framework: Some("fastapi".to_string()),
        explanation: "These FastAPI route handlers register the same HTTP method and path."
            .to_string(),
        remediation: "Remove one route, merge the handlers, or change one path/method combination."
            .to_string(),
        detection_reason:
            "FastAPI route metadata was grouped by HTTP method and route path.".to_string(),
        autofix: AutofixSafety::SuggestionOnly,
        autofix_explanation:
            "Duplicate routes are not auto-fixed because choosing which handler should own an API path is a product decision."
                .to_string(),
        fixes: Vec::new(),
        metadata,
        is_suppressed: false,
        suppression: None,
    }
}

fn framework_for_kind(kind: DefinitionKind) -> Option<&'static str> {
    match kind {
        DefinitionKind::ReactComponent | DefinitionKind::ReactHook => Some("react"),
        DefinitionKind::FastApiRoute | DefinitionKind::FastApiDependency => Some("fastapi"),
        _ => None,
    }
}

fn owner_context(definition: &Definition) -> Option<String> {
    definition
        .qualified_name
        .rsplit_once('.')
        .map(|(owner, _)| owner.to_string())
}

fn scope_key(definition: &Definition) -> String {
    format!(
        "{}::{}",
        normalize_path(&definition.file),
        owner_context(definition).unwrap_or_default()
    )
}

fn owners_are_similar(owners: &BTreeSet<String>) -> bool {
    if owners.len() < 2 {
        return false;
    }
    let token_sets = owners
        .iter()
        .map(|owner| owner_tokens(owner))
        .collect::<Vec<_>>();
    for index in 0..token_sets.len() {
        for other in token_sets.iter().skip(index + 1) {
            if token_sets[index].iter().any(|token| other.contains(token)) {
                return true;
            }
        }
    }
    false
}

fn owner_tokens(owner: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    let mut current = String::new();
    for character in owner.chars() {
        if character == '_' || character == '-' || character == '.' {
            push_owner_token(&mut tokens, &mut current);
            continue;
        }
        if character.is_ascii_uppercase() && !current.is_empty() {
            push_owner_token(&mut tokens, &mut current);
        }
        current.push(character.to_ascii_lowercase());
    }
    push_owner_token(&mut tokens, &mut current);
    tokens
}

fn push_owner_token(tokens: &mut BTreeSet<String>, current: &mut String) {
    if current.len() >= 4 {
        tokens.insert(std::mem::take(current));
    } else {
        current.clear();
    }
}

fn directory_key(path: &Path) -> String {
    path.parent()
        .map(normalize_path)
        .unwrap_or_else(|| ".".to_string())
}

pub fn render_symbols_snapshot(symbols: &FileSymbols) -> String {
    let mut output = String::new();
    for definition in &symbols.definitions {
        output.push_str(&format!(
            "{} {} {} [{}]\n",
            definition.language.label(),
            definition.kind.label(),
            definition.qualified_name,
            definition.visibility.label()
        ));
    }
    for import in &symbols.imports {
        output.push_str(&format!(
            "import {} {}\n",
            import.language.label(),
            import.module
        ));
    }
    output
}

fn stable_definition_id(
    language: Language,
    kind: DefinitionKind,
    qualified_name: &str,
    file: &Path,
    span: Span,
) -> DefinitionId {
    DefinitionId(stable_key(&format!(
        "{}|{}|{}|{}|{}:{}",
        language.label(),
        kind.label(),
        normalize_path(file),
        qualified_name,
        span.start,
        span.end
    )))
}

fn stable_key(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("{digest:x}")
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn module_key(path: &Path) -> String {
    path.parent()
        .map(normalize_path)
        .unwrap_or_else(|| ".".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(line: usize) -> Span {
        Span {
            start: line,
            end: line + 1,
            start_position: codehealth_parser::LineColumn { line, column: 1 },
            end_position: codehealth_parser::LineColumn { line, column: 2 },
        }
    }

    #[test]
    fn duplicate_name_findings_are_built_from_symbol_index() {
        let mut index = SymbolIndex::default();
        let mut left = Definition::new(
            Language::TypeScript,
            DefinitionKind::Function,
            "load",
            "load",
            "a.ts",
            span(1),
        );
        left.is_exported = true;
        let mut right = Definition::new(
            Language::TypeScript,
            DefinitionKind::Function,
            "load",
            "load",
            "b.ts",
            span(1),
        );
        right.is_exported = true;
        index.definitions.push(left);
        index.definitions.push(right);
        index.finalize();

        let findings = find_duplicate_name_findings(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, DUPLICATE_NAME_RULE);
    }

    #[test]
    fn common_method_names_are_suppressed_without_suspicious_context() {
        let mut index = SymbolIndex::default();
        let mut left = Definition::new(
            Language::TypeScript,
            DefinitionKind::Method,
            "render",
            "UserCard.render",
            "cards/user.tsx",
            span(1),
        );
        left.visibility = Visibility::Public;
        let mut right = Definition::new(
            Language::TypeScript,
            DefinitionKind::Method,
            "render",
            "InvoicePanel.render",
            "panels/invoice.tsx",
            span(1),
        );
        right.visibility = Visibility::Public;
        index.definitions.push(left);
        index.definitions.push(right);
        index.finalize();

        let findings = find_duplicate_name_findings(&index);

        assert!(findings.is_empty());
    }

    #[test]
    fn similar_method_contexts_are_reported() {
        let mut index = SymbolIndex::default();
        index.definitions.push(Definition::new(
            Language::TypeScript,
            DefinitionKind::Method,
            "save",
            "UserRepository.save",
            "repositories/user.ts",
            span(1),
        ));
        index.definitions.push(Definition::new(
            Language::TypeScript,
            DefinitionKind::Method,
            "save",
            "OrderRepository.save",
            "repositories/order.ts",
            span(1),
        ));
        index.finalize();

        let findings = find_duplicate_name_findings(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, DUPLICATE_NAME_METHOD_RULE);
        assert_eq!(
            findings[0].metadata["signals"],
            serde_json::json!(["same_directory", "similar_owner_context"])
        );
    }

    #[test]
    fn duplicate_fastapi_routes_are_reported() {
        let mut index = SymbolIndex::default();
        let mut left = Definition::new(
            Language::Python,
            DefinitionKind::FastApiRoute,
            "get_user",
            "get_user",
            "app.py",
            span(1),
        );
        let mut right = Definition::new(
            Language::Python,
            DefinitionKind::FastApiRoute,
            "read_user",
            "read_user",
            "router.py",
            span(1),
        );
        let route = FastApiRouteMetadata {
            method: "GET".to_string(),
            path: "/users/{user_id}".to_string(),
            ..FastApiRouteMetadata::default()
        };
        left.framework_tags
            .push(FrameworkTag::FastApiRoute(route.clone()));
        right.framework_tags.push(FrameworkTag::FastApiRoute(route));
        index.definitions.push(left);
        index.definitions.push(right);
        index.finalize();

        let findings = find_duplicate_fastapi_route_findings(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, FASTAPI_DUPLICATE_ROUTE_RULE);
    }

    #[test]
    fn symbol_snapshot_is_stable() {
        let mut symbols = FileSymbols {
            path: PathBuf::from("a.ts"),
            ..FileSymbols::default()
        };
        symbols.definitions.push(Definition::new(
            Language::Tsx,
            DefinitionKind::ReactComponent,
            "UserCard",
            "UserCard",
            "a.tsx",
            span(1),
        ));

        insta::assert_snapshot!(render_symbols_snapshot(&symbols), @"tsx react_component UserCard [private]
");
    }
}
