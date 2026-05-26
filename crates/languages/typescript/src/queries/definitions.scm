(function_declaration
  name: (identifier) @definition.name) @definition.function

(class_declaration
  name: (_) @definition.name) @definition.class

(method_definition
  name: (_) @definition.name) @definition.method

(variable_declarator
  name: (identifier) @definition.name
  value: (arrow_function) @definition.body) @definition.arrow

(variable_declarator
  name: (identifier) @definition.name
  value: (call_expression) @definition.body) @definition.call
