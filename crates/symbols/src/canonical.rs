use crate::{Definition, DefinitionKind};
use codehealth_parser::{child_by_field_name, named_children, Span, SyntaxTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

pub const CANONICAL_AST_VERSION: &str = "canonical_ast_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonParam {
    pub slot: SymbolSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSlot {
    Param(usize),
    Local(usize),
    Receiver,
    Named(String),
}

impl SymbolSlot {
    pub fn label(&self) -> String {
        match self {
            Self::Param(index) => format!("PARAM_{index}"),
            Self::Local(index) => format!("LOCAL_{index}"),
            Self::Receiver => "RECEIVER".to_string(),
            Self::Named(name) => format!("NAMED:{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteralKind {
    String(Option<String>),
    Number(Option<String>),
    Boolean(Option<String>),
    Null,
    Other(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonNode {
    Function {
        params: Vec<CanonParam>,
        body: Box<CanonNode>,
        flags: Vec<String>,
        decorators: Vec<String>,
    },
    Params(Vec<CanonParam>),
    Block(Vec<CanonNode>),
    Return(Box<CanonNode>),
    If {
        condition: Box<CanonNode>,
        then_branch: Box<CanonNode>,
        else_branch: Option<Box<CanonNode>>,
    },
    Binary {
        op: String,
        left: Box<CanonNode>,
        right: Box<CanonNode>,
    },
    Call {
        callee: String,
        args: Vec<CanonNode>,
    },
    Member {
        object: Box<CanonNode>,
        property: String,
    },
    Identifier(SymbolSlot),
    Literal(LiteralKind),
    Assign {
        target: Box<CanonNode>,
        value: Box<CanonNode>,
    },
    Await(Box<CanonNode>),
    Match(Vec<CanonNode>),
    Try(Vec<CanonNode>),
    Macro {
        name: String,
    },
    Unsafe(Box<CanonNode>),
    Opaque {
        node_kind: String,
    },
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteralPolicy {
    Preserve,
    Normalize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierSlotBinding {
    pub original: String,
    pub slot: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralFingerprint {
    pub version: String,
    pub literal_policy: LiteralPolicy,
    pub stable_hash_hex: String,
    pub serialization: String,
    pub node_count: usize,
    pub opaque_node_count: usize,
    pub token_estimate: usize,
    pub parameter_count: usize,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_unsafe: bool,
    pub return_shape: String,
    pub call_names: Vec<String>,
    pub framework_context: Vec<String>,
    pub slot_bindings: Vec<IdentifierSlotBinding>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalizationOptions {
    pub normalize_literals: bool,
}

impl CanonicalizationOptions {
    pub fn preserve_literals() -> Self {
        Self {
            normalize_literals: false,
        }
    }

    pub fn normalize_literals() -> Self {
        Self {
            normalize_literals: true,
        }
    }

    fn literal_policy(self) -> LiteralPolicy {
        if self.normalize_literals {
            LiteralPolicy::Normalize
        } else {
            LiteralPolicy::Preserve
        }
    }
}

pub fn populate_structural_fingerprints(tree: &SyntaxTree, definition: &mut Definition) {
    definition.structural_fingerprint = structural_fingerprint_for_definition(
        tree,
        definition,
        CanonicalizationOptions::preserve_literals(),
    );
    definition.literal_normalized_structural_fingerprint = structural_fingerprint_for_definition(
        tree,
        definition,
        CanonicalizationOptions::normalize_literals(),
    );
}

pub fn structural_fingerprint_for_definition(
    tree: &SyntaxTree,
    definition: &Definition,
    options: CanonicalizationOptions,
) -> Option<StructuralFingerprint> {
    if !canonical_definition_kind(definition.kind) {
        return None;
    }
    let root = find_definition_node(tree, definition)?;
    let mut context = CanonContext::new(definition, options, &tree.source.source);
    let body = select_body_node(root).unwrap_or(root);
    let body_node = context.canonical_body(body, true);
    let flags = structural_flags(tree, root, definition);
    let decorators = definition
        .decorators
        .iter()
        .map(|decorator| decorator.name.clone())
        .chain(
            definition
                .attributes
                .iter()
                .map(|attribute| attribute.name.clone()),
        )
        .collect::<Vec<_>>();
    let params = context.params.clone();
    let node = CanonNode::Function {
        params,
        body: Box::new(body_node),
        flags,
        decorators,
    };
    let serialization = serialize_canon_node(&node);
    let stable_hash = Sha256::digest(
        format!(
            "{}|{:?}|{}",
            CANONICAL_AST_VERSION,
            options.literal_policy(),
            serialization
        )
        .as_bytes(),
    );
    let stats = canon_stats(&node);
    let mut call_names = context.call_names.into_iter().collect::<Vec<_>>();
    call_names.sort();
    let mut framework_context = definition
        .framework_tags
        .iter()
        .map(|tag| tag.label())
        .collect::<Vec<_>>();
    framework_context.sort();
    framework_context.dedup();
    let mut slot_bindings = context.slot_bindings;
    slot_bindings.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.slot.cmp(&right.slot))
            .then_with(|| left.original.cmp(&right.original))
    });

    Some(StructuralFingerprint {
        version: CANONICAL_AST_VERSION.to_string(),
        literal_policy: options.literal_policy(),
        stable_hash_hex: format!("{stable_hash:x}"),
        serialization,
        node_count: stats.node_count,
        opaque_node_count: stats.opaque_node_count,
        token_estimate: stats.token_estimate,
        parameter_count: definition.signature.parameters.len(),
        is_async: definition.is_async,
        is_generator: tree.text_for_node(root).contains("function*"),
        is_unsafe: tree.text_for_node(root).contains("unsafe"),
        return_shape: return_shape(&node),
        call_names,
        framework_context,
        slot_bindings,
        warnings: context.warnings,
    })
}

fn canonical_definition_kind(kind: DefinitionKind) -> bool {
    matches!(
        kind,
        DefinitionKind::Function
            | DefinitionKind::Method
            | DefinitionKind::ReactComponent
            | DefinitionKind::ReactHook
            | DefinitionKind::FastApiRoute
            | DefinitionKind::FastApiDependency
    )
}

fn find_definition_node<'tree>(
    tree: &'tree SyntaxTree,
    definition: &Definition,
) -> Option<Node<'tree>> {
    let preferred = definition.body_span.or(Some(definition.span))?;
    find_smallest_node_covering_span(tree.root_node(), preferred)
        .or_else(|| find_exact_span_node(tree.root_node(), preferred))
}

fn find_exact_span_node<'tree>(node: Node<'tree>, span: Span) -> Option<Node<'tree>> {
    if node.start_byte() == span.start && node.end_byte() == span.end {
        return Some(node);
    }
    named_children(node)
        .into_iter()
        .find_map(|child| find_exact_span_node(child, span))
}

fn find_smallest_node_covering_span<'tree>(node: Node<'tree>, span: Span) -> Option<Node<'tree>> {
    if node.start_byte() > span.start || node.end_byte() < span.end {
        return None;
    }
    for child in named_children(node) {
        if let Some(match_node) = find_smallest_node_covering_span(child, span) {
            return Some(match_node);
        }
    }
    Some(node)
}

fn select_body_node(node: Node<'_>) -> Option<Node<'_>> {
    child_by_field_name(node, "body").or_else(|| {
        if matches!(
            node.kind(),
            "statement_block"
                | "block"
                | "arrow_function"
                | "function_declaration"
                | "function_definition"
                | "function_item"
        ) {
            Some(node)
        } else {
            None
        }
    })
}

struct CanonContext {
    source: String,
    definition_kind: DefinitionKind,
    options: CanonicalizationOptions,
    params: Vec<CanonParam>,
    param_slots: BTreeMap<String, usize>,
    local_slots: BTreeMap<String, usize>,
    slot_bindings: Vec<IdentifierSlotBinding>,
    call_names: BTreeSet<String>,
    warnings: Vec<String>,
}

impl CanonContext {
    fn new(definition: &Definition, options: CanonicalizationOptions, source: &str) -> Self {
        let mut params = Vec::new();
        let mut param_slots = BTreeMap::new();
        let mut slot_bindings = Vec::new();
        for parameter in &definition.signature.parameters {
            if parameter.name.is_empty() || matches!(parameter.name.as_str(), "self" | "cls") {
                continue;
            }
            let index = param_slots.len();
            param_slots.insert(parameter.name.clone(), index);
            params.push(CanonParam {
                slot: SymbolSlot::Param(index),
            });
            slot_bindings.push(IdentifierSlotBinding {
                original: parameter.name.clone(),
                slot: format!("PARAM_{index}"),
                role: "parameter".to_string(),
            });
        }
        Self {
            source: source.to_string(),
            definition_kind: definition.kind,
            options,
            params,
            param_slots,
            local_slots: BTreeMap::new(),
            slot_bindings,
            call_names: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn canonical_body(&mut self, node: Node<'_>, expression_body: bool) -> CanonNode {
        if matches!(
            node.kind(),
            "arrow_function" | "function_declaration" | "function_definition" | "function_item"
        ) {
            if let Some(body) = child_by_field_name(node, "body") {
                return self.canonical_body(body, true);
            }
        }
        if is_block(node.kind()) {
            let children = named_children(node)
                .into_iter()
                .filter(|child| !is_trivia(child.kind()))
                .collect::<Vec<_>>();
            if children.len() == 1 && is_return_like(children[0].kind()) {
                return self.canonical_node(children[0]);
            }
            let nodes = children
                .into_iter()
                .map(|child| self.canonical_node(child))
                .filter(|child| !matches!(child, CanonNode::Empty))
                .collect::<Vec<_>>();
            return CanonNode::Block(nodes);
        }
        let node = self.canonical_node(node);
        if expression_body {
            CanonNode::Return(Box::new(node))
        } else {
            node
        }
    }

    fn canonical_node(&mut self, node: Node<'_>) -> CanonNode {
        match node.kind() {
            kind if is_trivia(kind) => CanonNode::Empty,
            "return_statement" | "return_expression" => {
                let expression = first_named_non_trivia_child(node)
                    .map(|child| self.canonical_node(child))
                    .unwrap_or(CanonNode::Empty);
                CanonNode::Return(Box::new(expression))
            }
            "if_statement" | "if_expression" => self.canonical_if(node),
            "binary_expression" | "comparison_operator" | "boolean_operator" => {
                self.canonical_binary(node)
            }
            "call_expression" | "call" => self.canonical_call(node),
            "member_expression" | "attribute" | "field_expression" => self.canonical_member(node),
            "identifier" | "property_identifier" | "shorthand_property_identifier" => {
                let name = self.node_text(node);
                self.identifier_node(&name, IdentifierRole::Use)
            }
            "self" => self.identifier_node("self", IdentifierRole::Use),
            "number" | "integer" | "integer_literal" | "float" | "float_literal" => {
                CanonNode::Literal(self.literal_kind("number", node))
            }
            "string" | "string_literal" | "true" | "false" | "null" | "none" | "None" => {
                CanonNode::Literal(self.literal_kind(node.kind(), node))
            }
            "assignment" | "assignment_expression" | "augmented_assignment_expression" => {
                self.canonical_assignment(node)
            }
            "variable_declarator" => self.canonical_variable_declarator(node),
            "lexical_declaration" | "variable_declaration" | "expression_statement" => {
                self.canonical_children_as_block(node)
            }
            "await_expression" => {
                let child = first_named_non_trivia_child(node)
                    .map(|child| self.canonical_node(child))
                    .unwrap_or(CanonNode::Empty);
                CanonNode::Await(Box::new(child))
            }
            "match_expression" => CanonNode::Match(self.canonical_named_children(node)),
            "try_statement" | "try_expression" => {
                CanonNode::Try(self.canonical_named_children(node))
            }
            "macro_invocation" => CanonNode::Macro {
                name: macro_name(&self.source, node).unwrap_or_else(|| "macro".to_string()),
            },
            "unsafe_block" => {
                let child = child_by_field_name(node, "body")
                    .map(|child| self.canonical_node(child))
                    .unwrap_or_else(|| self.canonical_children_as_block(node));
                CanonNode::Unsafe(Box::new(child))
            }
            "statement_block" | "block" => self.canonical_body(node, false),
            _ => {
                let children = self.canonical_named_children(node);
                if children.is_empty() {
                    self.warnings
                        .push(format!("opaque node preserved for {}", node.kind()));
                    CanonNode::Opaque {
                        node_kind: node.kind().to_string(),
                    }
                } else if children.len() == 1 {
                    children.into_iter().next().unwrap_or(CanonNode::Empty)
                } else {
                    CanonNode::Block(children)
                }
            }
        }
    }

    fn canonical_if(&mut self, node: Node<'_>) -> CanonNode {
        let condition = child_by_field_name(node, "condition")
            .or_else(|| named_children(node).into_iter().next())
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        let then_branch = child_by_field_name(node, "consequence")
            .or_else(|| child_by_field_name(node, "body"))
            .or_else(|| named_children(node).into_iter().nth(1))
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        let else_branch = child_by_field_name(node, "alternative")
            .map(|child| Box::new(self.canonical_node(child)));
        CanonNode::If {
            condition: Box::new(condition),
            then_branch: Box::new(then_branch),
            else_branch,
        }
    }

    fn canonical_binary(&mut self, node: Node<'_>) -> CanonNode {
        let left = child_by_field_name(node, "left")
            .or_else(|| named_children(node).into_iter().next())
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        let right = child_by_field_name(node, "right")
            .or_else(|| named_children(node).into_iter().nth(1))
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        CanonNode::Binary {
            op: operator_text(&self.source, node),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn canonical_call(&mut self, node: Node<'_>) -> CanonNode {
        let function = child_by_field_name(node, "function")
            .or_else(|| named_children(node).into_iter().next());
        let callee = function
            .map(|function| callee_name(&self.source, function))
            .unwrap_or_else(|| "call".to_string());
        self.call_names.insert(callee.clone());
        let args_node = child_by_field_name(node, "arguments").or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind().contains("argument"))
        });
        let args = args_node
            .map(|arguments| self.canonical_arguments(arguments))
            .unwrap_or_default();
        CanonNode::Call { callee, args }
    }

    fn canonical_arguments(&mut self, node: Node<'_>) -> Vec<CanonNode> {
        named_children(node)
            .into_iter()
            .filter(|child| !is_trivia(child.kind()))
            .map(|child| {
                if child.kind() == "keyword_argument" {
                    let name = child_by_field_name(child, "name")
                        .map(|name| self.node_text(name))
                        .unwrap_or_default();
                    let value = child_by_field_name(child, "value")
                        .map(|value| self.canonical_node(value))
                        .unwrap_or(CanonNode::Empty);
                    CanonNode::Call {
                        callee: format!("kw:{name}"),
                        args: vec![value],
                    }
                } else {
                    self.canonical_node(child)
                }
            })
            .collect()
    }

    fn canonical_member(&mut self, node: Node<'_>) -> CanonNode {
        let object = child_by_field_name(node, "object")
            .or_else(|| named_children(node).into_iter().next())
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        let property = child_by_field_name(node, "property")
            .or_else(|| child_by_field_name(node, "attribute"))
            .or_else(|| child_by_field_name(node, "field"))
            .or_else(|| named_children(node).into_iter().last())
            .map(|property| self.node_text(property))
            .unwrap_or_else(|| "property".to_string());
        CanonNode::Member {
            object: Box::new(object),
            property,
        }
    }

    fn canonical_assignment(&mut self, node: Node<'_>) -> CanonNode {
        let target = child_by_field_name(node, "left")
            .or_else(|| child_by_field_name(node, "pattern"))
            .or_else(|| named_children(node).into_iter().next())
            .map(|child| self.canonical_assignment_target(child))
            .unwrap_or(CanonNode::Empty);
        let value = child_by_field_name(node, "right")
            .or_else(|| child_by_field_name(node, "value"))
            .or_else(|| named_children(node).into_iter().nth(1))
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        CanonNode::Assign {
            target: Box::new(target),
            value: Box::new(value),
        }
    }

    fn canonical_variable_declarator(&mut self, node: Node<'_>) -> CanonNode {
        let target = child_by_field_name(node, "name")
            .map(|child| self.canonical_assignment_target(child))
            .unwrap_or(CanonNode::Empty);
        let value = child_by_field_name(node, "value")
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        CanonNode::Assign {
            target: Box::new(target),
            value: Box::new(value),
        }
    }

    fn canonical_assignment_target(&mut self, node: Node<'_>) -> CanonNode {
        if is_identifier_kind(node.kind()) {
            self.identifier_node(&self.node_text(node), IdentifierRole::LocalDefinition)
        } else {
            self.canonical_node(node)
        }
    }

    fn canonical_children_as_block(&mut self, node: Node<'_>) -> CanonNode {
        CanonNode::Block(self.canonical_named_children(node))
    }

    fn canonical_named_children(&mut self, node: Node<'_>) -> Vec<CanonNode> {
        named_children(node)
            .into_iter()
            .filter(|child| !is_trivia(child.kind()))
            .map(|child| self.canonical_node(child))
            .filter(|child| !matches!(child, CanonNode::Empty))
            .collect()
    }

    fn identifier_node(&mut self, name: &str, role: IdentifierRole) -> CanonNode {
        if matches!(name, "this" | "arguments") {
            return CanonNode::Identifier(SymbolSlot::Named(name.to_string()));
        }
        if matches!(name, "self" | "cls") && self.definition_kind == DefinitionKind::Method {
            return CanonNode::Identifier(SymbolSlot::Receiver);
        }
        if let Some(index) = self.param_slots.get(name) {
            return CanonNode::Identifier(SymbolSlot::Param(*index));
        }
        if matches!(role, IdentifierRole::LocalDefinition) {
            let index = if let Some(index) = self.local_slots.get(name) {
                *index
            } else {
                let index = self.local_slots.len();
                self.local_slots.insert(name.to_string(), index);
                self.slot_bindings.push(IdentifierSlotBinding {
                    original: name.to_string(),
                    slot: format!("LOCAL_{index}"),
                    role: "local".to_string(),
                });
                index
            };
            return CanonNode::Identifier(SymbolSlot::Local(index));
        }
        if let Some(index) = self.local_slots.get(name) {
            return CanonNode::Identifier(SymbolSlot::Local(*index));
        }
        CanonNode::Identifier(SymbolSlot::Named(name.to_string()))
    }

    fn literal_kind(&self, kind: &str, node: Node<'_>) -> LiteralKind {
        let value = if self.options.normalize_literals {
            None
        } else {
            Some(self.node_text(node))
        };
        match kind {
            "string" | "string_literal" => LiteralKind::String(value),
            "number" | "integer" | "integer_literal" | "float" | "float_literal" => {
                LiteralKind::Number(value)
            }
            "true" | "false" => LiteralKind::Boolean(value),
            "null" | "none" | "None" => LiteralKind::Null,
            _ => LiteralKind::Other(value),
        }
    }

    fn node_text(&self, node: Node<'_>) -> String {
        self.source
            .get(node.start_byte()..node.end_byte())
            .unwrap_or_default()
            .to_string()
    }
}

#[derive(Debug, Clone, Copy)]
enum IdentifierRole {
    Use,
    LocalDefinition,
}

fn is_identifier_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "property_identifier" | "shorthand_property_identifier" | "type_identifier"
    )
}

fn first_named_non_trivia_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| !is_trivia(child.kind()))
}

fn node_text(source: &str, node: Node<'_>) -> String {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .to_string()
}

fn callee_name(source: &str, node: Node<'_>) -> String {
    match node.kind() {
        "identifier" | "property_identifier" | "type_identifier" => node_text(source, node),
        "member_expression" | "attribute" | "field_expression" => {
            child_by_field_name(node, "property")
                .or_else(|| child_by_field_name(node, "attribute"))
                .or_else(|| child_by_field_name(node, "field"))
                .or_else(|| named_children(node).into_iter().last())
                .map(|property| node_text(source, property))
                .unwrap_or_else(|| "member_call".to_string())
        }
        "scoped_identifier" => node_text(source, node),
        _ => node.kind().to_string(),
    }
}

fn macro_name(source: &str, node: Node<'_>) -> Option<String> {
    child_by_field_name(node, "macro")
        .or_else(|| named_children(node).into_iter().next())
        .map(|macro_node| node_text(source, macro_node))
}

fn is_block(kind: &str) -> bool {
    matches!(
        kind,
        "statement_block" | "block" | "class_body" | "declaration_list"
    )
}

fn is_return_like(kind: &str) -> bool {
    matches!(kind, "return_statement" | "return_expression")
}

fn is_trivia(kind: &str) -> bool {
    matches!(kind, "comment" | ";" | "," | ":" | "{" | "}")
}

fn operator_text(source: &str, node: Node<'_>) -> String {
    let text = node_text(source, node);
    for op in [
        "===", "!==", "??", ">=", "<=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", ">", "<",
        "and", "or", "is", "in",
    ] {
        if text.contains(op) {
            return op.to_string();
        }
    }
    node.kind().to_string()
}

fn structural_flags(tree: &SyntaxTree, node: Node<'_>, definition: &Definition) -> Vec<String> {
    let mut flags = Vec::new();
    if definition.is_async {
        flags.push("async".to_string());
    }
    let text = tree.text_for_node(node);
    if text.contains("function*") {
        flags.push("generator".to_string());
    }
    if text.contains("unsafe") {
        flags.push("unsafe".to_string());
    }
    flags
}

fn serialize_canon_node(node: &CanonNode) -> String {
    match node {
        CanonNode::Function {
            params,
            body,
            flags,
            decorators,
        } => format!(
            "Function(flags=[{}],decorators=[{}],params=[{}],body={})",
            flags.join(","),
            decorators.join(","),
            params
                .iter()
                .map(|param| param.slot.label())
                .collect::<Vec<_>>()
                .join(","),
            serialize_canon_node(body)
        ),
        CanonNode::Params(params) => format!(
            "Params({})",
            params
                .iter()
                .map(|param| param.slot.label())
                .collect::<Vec<_>>()
                .join(",")
        ),
        CanonNode::Block(children) => format!("Block({})", serialize_children(children)),
        CanonNode::Return(value) => format!("Return({})", serialize_canon_node(value)),
        CanonNode::If {
            condition,
            then_branch,
            else_branch,
        } => format!(
            "If({},then={},else={})",
            serialize_canon_node(condition),
            serialize_canon_node(then_branch),
            else_branch
                .as_ref()
                .map(|node| serialize_canon_node(node))
                .unwrap_or_else(|| "None".to_string())
        ),
        CanonNode::Binary { op, left, right } => format!(
            "Binary({},{},{})",
            op,
            serialize_canon_node(left),
            serialize_canon_node(right)
        ),
        CanonNode::Call { callee, args } => {
            format!("Call({callee},[{}])", serialize_children(args))
        }
        CanonNode::Member { object, property } => member_path(node)
            .map(|path| format!("Member({path})"))
            .unwrap_or_else(|| format!("Member({},.{property})", serialize_canon_node(object))),
        CanonNode::Identifier(slot) => format!("Identifier({})", slot.label()),
        CanonNode::Literal(kind) => format!("Literal({kind:?})"),
        CanonNode::Assign { target, value } => format!(
            "Assign({}, {})",
            serialize_canon_node(target),
            serialize_canon_node(value)
        ),
        CanonNode::Await(value) => format!("Await({})", serialize_canon_node(value)),
        CanonNode::Match(children) => format!("Match({})", serialize_children(children)),
        CanonNode::Try(children) => format!("Try({})", serialize_children(children)),
        CanonNode::Macro { name } => format!("Macro({name})"),
        CanonNode::Unsafe(value) => format!("Unsafe({})", serialize_canon_node(value)),
        CanonNode::Opaque { node_kind } => format!("Opaque({node_kind})"),
        CanonNode::Empty => "Empty".to_string(),
    }
}

fn member_path(node: &CanonNode) -> Option<String> {
    match node {
        CanonNode::Identifier(slot) => Some(slot.label()),
        CanonNode::Member { object, property } => {
            Some(format!("{}.{}", member_path(object)?, property))
        }
        _ => None,
    }
}

fn serialize_children(children: &[CanonNode]) -> String {
    children
        .iter()
        .map(serialize_canon_node)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Default)]
struct CanonStats {
    node_count: usize,
    opaque_node_count: usize,
    token_estimate: usize,
}

fn canon_stats(node: &CanonNode) -> CanonStats {
    let mut stats = CanonStats::default();
    accumulate_stats(node, &mut stats);
    stats
}

fn accumulate_stats(node: &CanonNode, stats: &mut CanonStats) {
    stats.node_count += 1;
    stats.token_estimate += 1;
    match node {
        CanonNode::Function { params, body, .. } => {
            stats.token_estimate += params.len();
            accumulate_stats(body, stats);
        }
        CanonNode::Params(params) => stats.token_estimate += params.len(),
        CanonNode::Block(children) | CanonNode::Match(children) | CanonNode::Try(children) => {
            for child in children {
                accumulate_stats(child, stats);
            }
        }
        CanonNode::Return(value) | CanonNode::Await(value) | CanonNode::Unsafe(value) => {
            accumulate_stats(value, stats);
        }
        CanonNode::If {
            condition,
            then_branch,
            else_branch,
        } => {
            accumulate_stats(condition, stats);
            accumulate_stats(then_branch, stats);
            if let Some(else_branch) = else_branch {
                accumulate_stats(else_branch, stats);
            }
        }
        CanonNode::Binary { left, right, .. } => {
            accumulate_stats(left, stats);
            accumulate_stats(right, stats);
        }
        CanonNode::Call { args, .. } => {
            for arg in args {
                accumulate_stats(arg, stats);
            }
        }
        CanonNode::Member { object, .. } => accumulate_stats(object, stats),
        CanonNode::Assign { target, value } => {
            accumulate_stats(target, stats);
            accumulate_stats(value, stats);
        }
        CanonNode::Opaque { .. } => stats.opaque_node_count += 1,
        CanonNode::Identifier(_)
        | CanonNode::Literal(_)
        | CanonNode::Macro { .. }
        | CanonNode::Empty => {}
    }
}

fn return_shape(node: &CanonNode) -> String {
    match node {
        CanonNode::Function { body, .. } => return_shape(body),
        CanonNode::Return(value) => node_shape(value),
        CanonNode::Block(children) => children
            .iter()
            .find_map(|child| {
                if matches!(child, CanonNode::Return(_)) {
                    Some(return_shape(child))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "block".to_string()),
        _ => node_shape(node),
    }
}

fn node_shape(node: &CanonNode) -> String {
    match node {
        CanonNode::Binary { .. } => "binary".to_string(),
        CanonNode::Call { .. } => "call".to_string(),
        CanonNode::Member { .. } => "member".to_string(),
        CanonNode::Identifier(_) => "identifier".to_string(),
        CanonNode::Literal(_) => "literal".to_string(),
        CanonNode::If { .. } => "if".to_string(),
        CanonNode::Match(_) => "match".to_string(),
        CanonNode::Try(_) => "try".to_string(),
        CanonNode::Block(_) => "block".to_string(),
        CanonNode::Return(value) => node_shape(value),
        CanonNode::Assign { .. } => "assign".to_string(),
        CanonNode::Await(value) => format!("await:{}", node_shape(value)),
        CanonNode::Macro { .. } => "macro".to_string(),
        CanonNode::Unsafe(value) => format!("unsafe:{}", node_shape(value)),
        CanonNode::Function { .. } => "function".to_string(),
        CanonNode::Params(_) => "params".to_string(),
        CanonNode::Opaque { node_kind } => format!("opaque:{node_kind}"),
        CanonNode::Empty => "empty".to_string(),
    }
}
