use crate::{Definition, DefinitionKind};
use codehealth_core::Confidence;
use codehealth_parser::{child_by_field_name, named_children, Span, SyntaxTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

pub const CANONICAL_AST_VERSION: &str = "canonical_ast_v1";
pub const SEMANTIC_AST_VERSION: &str = "semantic_ast_v1";

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
    Unary {
        op: String,
        value: Box<CanonNode>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticFingerprint {
    pub version: String,
    pub stable_hash_hex: String,
    pub serialization: String,
    pub confidence: Confidence,
    pub rewrites: Vec<String>,
    pub skipped_rewrites: Vec<String>,
    pub safety_warnings: Vec<String>,
    pub type_evidence: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticOptions {
    pub property_reads_are_pure: bool,
    pub normalize_boolean_returns: bool,
    pub normalize_commutative_ops: bool,
    pub normalize_comparisons: bool,
}

impl Default for SemanticOptions {
    fn default() -> Self {
        Self {
            property_reads_are_pure: false,
            normalize_boolean_returns: true,
            normalize_commutative_ops: true,
            normalize_comparisons: true,
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
    definition.semantic_fingerprint =
        semantic_fingerprint_for_definition(tree, definition, SemanticOptions::default());
    definition.property_read_semantic_fingerprint = semantic_fingerprint_for_definition(
        tree,
        definition,
        SemanticOptions {
            property_reads_are_pure: true,
            ..SemanticOptions::default()
        },
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

pub fn semantic_fingerprint_for_definition(
    tree: &SyntaxTree,
    definition: &Definition,
    options: SemanticOptions,
) -> Option<SemanticFingerprint> {
    if !canonical_definition_kind(definition.kind) {
        return None;
    }
    let root = find_definition_node(tree, definition)?;
    let mut context = CanonContext::new(
        definition,
        CanonicalizationOptions::preserve_literals(),
        &tree.source.source,
    );
    let body = select_body_node(root).unwrap_or(root);
    let body_node = context.canonical_body(body, true);
    let mut semantic_context = SemanticContext::new(definition, options);
    let body_node = semantic_context.normalize_body(body_node);
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
    let node = CanonNode::Function {
        params: context.params,
        body: Box::new(body_node),
        flags,
        decorators,
    };
    let serialization = serialize_canon_node(&node);
    let stable_hash =
        Sha256::digest(format!("{}|{}", SEMANTIC_AST_VERSION, serialization).as_bytes());

    Some(SemanticFingerprint {
        version: SEMANTIC_AST_VERSION.to_string(),
        stable_hash_hex: format!("{stable_hash:x}"),
        serialization,
        confidence: semantic_context.confidence,
        rewrites: sorted_set(semantic_context.rewrites),
        skipped_rewrites: sorted_set(semantic_context.skipped_rewrites),
        safety_warnings: sorted_set(semantic_context.safety_warnings),
        type_evidence: sorted_set(semantic_context.type_evidence),
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
            "unary_expression" | "not_operator" => self.canonical_unary(node),
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
            "string" | "string_literal" | "true" | "false" | "True" | "False" | "null" | "none"
            | "None" => CanonNode::Literal(self.literal_kind(node.kind(), node)),
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

    fn canonical_unary(&mut self, node: Node<'_>) -> CanonNode {
        let value = child_by_field_name(node, "argument")
            .or_else(|| named_children(node).into_iter().next())
            .map(|child| self.canonical_node(child))
            .unwrap_or(CanonNode::Empty);
        CanonNode::Unary {
            op: unary_operator_text(&self.source, node),
            value: Box::new(value),
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
            "true" | "false" | "True" | "False" => LiteralKind::Boolean(value),
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

fn unary_operator_text(source: &str, node: Node<'_>) -> String {
    let node_text = node_text(source, node);
    let text = node_text.trim_start();
    if text.starts_with('!') {
        return "!".to_string();
    }
    if text.starts_with("not ") {
        return "not".to_string();
    }
    if text.starts_with('-') {
        return "-".to_string();
    }
    node.kind().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticScalarType {
    Numeric,
    Boolean,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticSource {
    TypeAnnotation,
    Literal,
    Derived,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemanticFacts {
    pure: bool,
    scalar_type: Option<SemanticScalarType>,
    source: SemanticSource,
}

impl SemanticFacts {
    fn unknown_pure() -> Self {
        Self {
            pure: true,
            scalar_type: None,
            source: SemanticSource::Unknown,
        }
    }

    fn impure() -> Self {
        Self {
            pure: false,
            scalar_type: None,
            source: SemanticSource::Unknown,
        }
    }

    fn literal(scalar_type: SemanticScalarType) -> Self {
        Self {
            pure: true,
            scalar_type: Some(scalar_type),
            source: SemanticSource::Literal,
        }
    }

    fn derived(scalar_type: SemanticScalarType) -> Self {
        Self {
            pure: true,
            scalar_type: Some(scalar_type),
            source: SemanticSource::Derived,
        }
    }

    fn typed(scalar_type: SemanticScalarType) -> Self {
        Self {
            pure: true,
            scalar_type: Some(scalar_type),
            source: SemanticSource::TypeAnnotation,
        }
    }

    fn is_numeric(self) -> bool {
        self.scalar_type == Some(SemanticScalarType::Numeric)
    }

    fn is_boolean(self) -> bool {
        self.scalar_type == Some(SemanticScalarType::Boolean)
    }

    fn is_literal_numeric(self) -> bool {
        self.is_numeric() && self.source == SemanticSource::Literal
    }
}

#[derive(Debug, Clone)]
struct SemanticResult {
    node: CanonNode,
    facts: SemanticFacts,
}

struct SemanticContext<'a> {
    definition: &'a Definition,
    options: SemanticOptions,
    param_types: BTreeMap<usize, SemanticScalarType>,
    confidence: Confidence,
    rewrites: BTreeSet<String>,
    skipped_rewrites: BTreeSet<String>,
    safety_warnings: BTreeSet<String>,
    type_evidence: BTreeSet<String>,
}

impl<'a> SemanticContext<'a> {
    fn new(definition: &'a Definition, options: SemanticOptions) -> Self {
        let mut param_types = BTreeMap::new();
        let mut type_evidence = BTreeSet::new();
        for (slot, parameter) in definition
            .signature
            .parameters
            .iter()
            .filter(|parameter| !matches!(parameter.name.as_str(), "" | "self" | "cls"))
            .enumerate()
        {
            let Some(annotation) = parameter.type_annotation.as_deref() else {
                continue;
            };
            let Some(scalar_type) = parameter_semantic_type(definition.language, annotation) else {
                continue;
            };
            param_types.insert(slot, scalar_type);
            type_evidence.insert(format!(
                "{}:param{slot}:{}",
                definition.language.label(),
                semantic_type_label(scalar_type)
            ));
        }

        Self {
            definition,
            options,
            param_types,
            confidence: Confidence::High,
            rewrites: BTreeSet::new(),
            skipped_rewrites: BTreeSet::new(),
            safety_warnings: BTreeSet::new(),
            type_evidence,
        }
    }

    fn normalize_body(&mut self, node: CanonNode) -> CanonNode {
        self.normalize_node(node).node
    }

    fn normalize_node(&mut self, node: CanonNode) -> SemanticResult {
        match node {
            CanonNode::Function {
                params,
                body,
                flags,
                decorators,
            } => {
                let body = self.normalize_node(*body).node;
                SemanticResult {
                    node: CanonNode::Function {
                        params,
                        body: Box::new(body),
                        flags,
                        decorators,
                    },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Params(params) => SemanticResult {
                node: CanonNode::Params(params),
                facts: SemanticFacts::unknown_pure(),
            },
            CanonNode::Block(children) => self.normalize_block(children),
            CanonNode::Return(value) => {
                let value = self.normalize_node(*value);
                let facts = value.facts;
                if let CanonNode::Return(inner) = value.node {
                    self.rewrites
                        .insert("nested_return_normalization".to_string());
                    return SemanticResult {
                        node: CanonNode::Return(inner),
                        facts,
                    };
                }
                SemanticResult {
                    node: CanonNode::Return(Box::new(value.node)),
                    facts,
                }
            }
            CanonNode::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let condition = self.normalize_node(*condition);
                let then_branch = self.normalize_node(*then_branch);
                let else_branch = else_branch.map(|branch| self.normalize_node(*branch));
                SemanticResult {
                    node: CanonNode::If {
                        condition: Box::new(condition.node),
                        then_branch: Box::new(then_branch.node),
                        else_branch: else_branch.map(|branch| Box::new(branch.node)),
                    },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Binary { op, left, right } => self.normalize_binary(op, *left, *right),
            CanonNode::Unary { op, value } => {
                let value = self.normalize_node(*value);
                let facts = if matches!(op.as_str(), "!" | "not") && value.facts.pure {
                    SemanticFacts::derived(SemanticScalarType::Boolean)
                } else if value.facts.pure {
                    SemanticFacts::unknown_pure()
                } else {
                    SemanticFacts::impure()
                };
                SemanticResult {
                    node: CanonNode::Unary {
                        op,
                        value: Box::new(value.node),
                    },
                    facts,
                }
            }
            CanonNode::Call { callee, args } => {
                let args = args
                    .into_iter()
                    .map(|arg| self.normalize_node(arg).node)
                    .collect::<Vec<_>>();
                self.skipped_rewrites
                    .insert("call_expression_effectful".to_string());
                SemanticResult {
                    node: CanonNode::Call { callee, args },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Member { object, property } => {
                let object = self.normalize_node(*object);
                let facts = if self.options.property_reads_are_pure && object.facts.pure {
                    self.safety_warnings.insert(
                        "property reads configured as pure; getters may still have effects"
                            .to_string(),
                    );
                    SemanticFacts::unknown_pure()
                } else {
                    self.skipped_rewrites
                        .insert("property_read_not_configured_pure".to_string());
                    SemanticFacts::impure()
                };
                SemanticResult {
                    node: CanonNode::Member {
                        object: Box::new(object.node),
                        property,
                    },
                    facts,
                }
            }
            CanonNode::Identifier(slot) => {
                let facts = match slot {
                    SymbolSlot::Param(index) => self
                        .param_types
                        .get(&index)
                        .copied()
                        .map(SemanticFacts::typed)
                        .unwrap_or_else(SemanticFacts::unknown_pure),
                    _ => SemanticFacts::unknown_pure(),
                };
                SemanticResult {
                    node: CanonNode::Identifier(slot),
                    facts,
                }
            }
            CanonNode::Literal(kind) => {
                let facts = match &kind {
                    LiteralKind::Number(_) => SemanticFacts::literal(SemanticScalarType::Numeric),
                    LiteralKind::Boolean(_) => SemanticFacts::literal(SemanticScalarType::Boolean),
                    LiteralKind::String(_) => SemanticFacts::literal(SemanticScalarType::String),
                    LiteralKind::Null | LiteralKind::Other(_) => SemanticFacts::unknown_pure(),
                };
                SemanticResult {
                    node: CanonNode::Literal(kind),
                    facts,
                }
            }
            CanonNode::Assign { target, value } => {
                let target = self.normalize_node(*target);
                let value = self.normalize_node(*value);
                self.skipped_rewrites
                    .insert("assignment_or_mutation_effectful".to_string());
                SemanticResult {
                    node: CanonNode::Assign {
                        target: Box::new(target.node),
                        value: Box::new(value.node),
                    },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Await(value) => {
                let value = self.normalize_node(*value);
                self.skipped_rewrites.insert("await_effectful".to_string());
                SemanticResult {
                    node: CanonNode::Await(Box::new(value.node)),
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Match(children) => SemanticResult {
                node: CanonNode::Match(
                    children
                        .into_iter()
                        .map(|child| self.normalize_node(child).node)
                        .collect(),
                ),
                facts: SemanticFacts::impure(),
            },
            CanonNode::Try(children) => SemanticResult {
                node: CanonNode::Try(
                    children
                        .into_iter()
                        .map(|child| self.normalize_node(child).node)
                        .collect(),
                ),
                facts: SemanticFacts::impure(),
            },
            CanonNode::Macro { name } => {
                self.skipped_rewrites
                    .insert("macro_or_panic_effectful".to_string());
                SemanticResult {
                    node: CanonNode::Macro { name },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Unsafe(value) => {
                let value = self.normalize_node(*value);
                self.skipped_rewrites.insert("unsafe_block".to_string());
                SemanticResult {
                    node: CanonNode::Unsafe(Box::new(value.node)),
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Opaque { node_kind } => {
                self.skipped_rewrites
                    .insert(format!("opaque_node:{node_kind}"));
                SemanticResult {
                    node: CanonNode::Opaque { node_kind },
                    facts: SemanticFacts::impure(),
                }
            }
            CanonNode::Empty => SemanticResult {
                node: CanonNode::Empty,
                facts: SemanticFacts::unknown_pure(),
            },
        }
    }

    fn normalize_block(&mut self, children: Vec<CanonNode>) -> SemanticResult {
        let children = children
            .into_iter()
            .map(|child| self.normalize_node(child).node)
            .collect::<Vec<_>>();

        if self.options.normalize_boolean_returns {
            if let Some(return_node) = self.boolean_return_rewrite(&children) {
                return SemanticResult {
                    facts: return_node.facts,
                    node: return_node.node,
                };
            }
        }

        SemanticResult {
            node: CanonNode::Block(children),
            facts: SemanticFacts::impure(),
        }
    }

    fn boolean_return_rewrite(&mut self, children: &[CanonNode]) -> Option<SemanticResult> {
        let [CanonNode::If {
            condition,
            then_branch,
            else_branch: None,
        }, trailing] = children
        else {
            return None;
        };
        let then_literal = returned_boolean_literal(then_branch)?;
        let trailing_literal = returned_boolean_literal(trailing)?;
        if then_literal == trailing_literal {
            return None;
        }

        let condition_result = self.normalize_node((**condition).clone());
        if !condition_result.facts.pure {
            self.skipped_rewrites
                .insert("boolean_return_condition_effectful".to_string());
            return None;
        }
        if !condition_result.facts.is_boolean() {
            self.confidence = self.confidence.min(Confidence::Medium);
            self.safety_warnings.insert(
                "boolean-return condition type was not proven boolean; truthiness may differ"
                    .to_string(),
            );
        }

        if then_literal {
            self.rewrites
                .insert("boolean_return_simplification".to_string());
            Some(SemanticResult {
                node: CanonNode::Return(Box::new(condition_result.node)),
                facts: SemanticFacts::derived(SemanticScalarType::Boolean),
            })
        } else {
            self.rewrites
                .insert("inverse_boolean_return_simplification".to_string());
            Some(SemanticResult {
                node: CanonNode::Return(Box::new(CanonNode::Unary {
                    op: "!".to_string(),
                    value: Box::new(condition_result.node),
                })),
                facts: SemanticFacts::derived(SemanticScalarType::Boolean),
            })
        }
    }

    fn normalize_binary(
        &mut self,
        op: String,
        left: CanonNode,
        right: CanonNode,
    ) -> SemanticResult {
        let left = self.normalize_node(left);
        let right = self.normalize_node(right);
        let mut op = op;
        let mut left_node = left.node;
        let mut right_node = right.node;
        let left_facts = left.facts;
        let right_facts = right.facts;

        if self.options.normalize_comparisons
            && matches!(op.as_str(), ">" | ">=")
            && self.safe_numeric_operands(left_facts, right_facts)
        {
            op = if op == ">" { "<" } else { "<=" }.to_string();
            std::mem::swap(&mut left_node, &mut right_node);
            self.rewrites.insert("comparison_inversion".to_string());
        }

        if self.options.normalize_commutative_ops {
            if matches!(op.as_str(), "+" | "*")
                && self.safe_numeric_operands(left_facts, right_facts)
            {
                let label = if op == "+" {
                    "commutative_numeric_add"
                } else {
                    "commutative_numeric_multiply"
                };
                if order_binary_operands(&mut left_node, &mut right_node) {
                    self.rewrites.insert(label.to_string());
                }
            } else if matches!(op.as_str(), "&&" | "||" | "and" | "or")
                && left_facts.pure
                && right_facts.pure
                && left_facts.is_boolean()
                && right_facts.is_boolean()
            {
                if order_binary_operands(&mut left_node, &mut right_node) {
                    self.rewrites
                        .insert("pure_boolean_operand_order".to_string());
                }
            } else if self.safe_equality_operands(&op, left_facts, right_facts) {
                if order_binary_operands(&mut left_node, &mut right_node) {
                    self.rewrites.insert("equality_operand_order".to_string());
                }
            } else if matches!(
                op.as_str(),
                "+" | "*" | "&&" | "||" | "and" | "or" | "==" | "!=" | "===" | "!=="
            ) {
                self.skipped_rewrites
                    .insert(format!("unsafe_operand_reorder:{op}"));
            }
        }

        let facts = self.binary_facts(&op, left_facts, right_facts);
        SemanticResult {
            node: CanonNode::Binary {
                op,
                left: Box::new(left_node),
                right: Box::new(right_node),
            },
            facts,
        }
    }

    fn binary_facts(
        &self,
        op: &str,
        left_facts: SemanticFacts,
        right_facts: SemanticFacts,
    ) -> SemanticFacts {
        let pure = left_facts.pure && right_facts.pure;
        if !pure {
            return SemanticFacts::impure();
        }
        if matches!(op, "<" | "<=" | ">" | ">=")
            && self.safe_numeric_operands(left_facts, right_facts)
        {
            return SemanticFacts::derived(SemanticScalarType::Boolean);
        }
        if self.safe_equality_operands(op, left_facts, right_facts) {
            return SemanticFacts::derived(SemanticScalarType::Boolean);
        }
        if matches!(op, "&&" | "||" | "and" | "or")
            && left_facts.is_boolean()
            && right_facts.is_boolean()
        {
            return SemanticFacts::derived(SemanticScalarType::Boolean);
        }
        if matches!(op, "+" | "*") && self.safe_numeric_operands(left_facts, right_facts) {
            return SemanticFacts::derived(SemanticScalarType::Numeric);
        }
        SemanticFacts::unknown_pure()
    }

    fn safe_numeric_operands(&self, left: SemanticFacts, right: SemanticFacts) -> bool {
        if !left.pure || !right.pure || !left.is_numeric() || !right.is_numeric() {
            return false;
        }
        match self.definition.language {
            crate::Language::TypeScript | crate::Language::Tsx | crate::Language::Rust => {
                matches!(
                    left.source,
                    SemanticSource::TypeAnnotation
                        | SemanticSource::Literal
                        | SemanticSource::Derived
                ) && matches!(
                    right.source,
                    SemanticSource::TypeAnnotation
                        | SemanticSource::Literal
                        | SemanticSource::Derived
                )
            }
            crate::Language::Python => left.is_literal_numeric() && right.is_literal_numeric(),
        }
    }

    fn safe_equality_operands(&self, op: &str, left: SemanticFacts, right: SemanticFacts) -> bool {
        if !left.pure || !right.pure {
            return false;
        }
        match self.definition.language {
            crate::Language::TypeScript | crate::Language::Tsx => {
                matches!(op, "===" | "!==")
                    && left.scalar_type.is_some()
                    && left.scalar_type == right.scalar_type
            }
            crate::Language::Rust | crate::Language::Python => {
                matches!(op, "==" | "!=")
                    && left.scalar_type.is_some()
                    && left.scalar_type == right.scalar_type
                    && matches!(
                        left.source,
                        SemanticSource::TypeAnnotation
                            | SemanticSource::Literal
                            | SemanticSource::Derived
                    )
                    && matches!(
                        right.source,
                        SemanticSource::TypeAnnotation
                            | SemanticSource::Literal
                            | SemanticSource::Derived
                    )
            }
        }
    }
}

fn parameter_semantic_type(
    language: crate::Language,
    annotation: &str,
) -> Option<SemanticScalarType> {
    let normalized = annotation
        .trim()
        .trim_start_matches(':')
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_end_matches(',')
        .trim();
    let lowered = normalized.to_ascii_lowercase();
    match language {
        crate::Language::TypeScript | crate::Language::Tsx => match lowered.as_str() {
            "number" => Some(SemanticScalarType::Numeric),
            "boolean" => Some(SemanticScalarType::Boolean),
            "string" => Some(SemanticScalarType::String),
            _ => None,
        },
        crate::Language::Rust => {
            if matches!(
                lowered.as_str(),
                "i8" | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "f32"
                    | "f64"
            ) {
                Some(SemanticScalarType::Numeric)
            } else if lowered == "bool" {
                Some(SemanticScalarType::Boolean)
            } else if matches!(lowered.as_str(), "str" | "string") {
                Some(SemanticScalarType::String)
            } else {
                None
            }
        }
        crate::Language::Python => {
            if lowered == "bool" {
                Some(SemanticScalarType::Boolean)
            } else {
                None
            }
        }
    }
}

fn semantic_type_label(scalar_type: SemanticScalarType) -> &'static str {
    match scalar_type {
        SemanticScalarType::Numeric => "numeric",
        SemanticScalarType::Boolean => "boolean",
        SemanticScalarType::String => "string",
    }
}

fn returned_boolean_literal(node: &CanonNode) -> Option<bool> {
    match node {
        CanonNode::Return(value) => boolean_literal(value),
        CanonNode::Block(children) if children.len() == 1 => returned_boolean_literal(&children[0]),
        _ => None,
    }
}

fn boolean_literal(node: &CanonNode) -> Option<bool> {
    match node {
        CanonNode::Literal(LiteralKind::Boolean(Some(value))) => match value.as_str() {
            "true" | "True" => Some(true),
            "false" | "False" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn order_binary_operands(left: &mut CanonNode, right: &mut CanonNode) -> bool {
    let left_serialized = serialize_canon_node(left);
    let right_serialized = serialize_canon_node(right);
    if right_serialized < left_serialized {
        std::mem::swap(left, right);
        true
    } else {
        false
    }
}

fn sorted_set(set: BTreeSet<String>) -> Vec<String> {
    set.into_iter().collect()
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
        CanonNode::Unary { op, value } => format!("Unary({op},{})", serialize_canon_node(value)),
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
        CanonNode::Return(value)
        | CanonNode::Unary { value, .. }
        | CanonNode::Await(value)
        | CanonNode::Unsafe(value) => {
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
        CanonNode::Unary { .. } => "unary".to_string(),
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
