import "@typespec/json-schema";
using TypeSpec.JsonSchema;

// Independent peer of clients/client-api.schema.json. Neither source is
// generated from or allowed to overwrite the other.
@jsonSchema
namespace SharedAuthClientApi;

@pattern("^[A-Za-z_][A-Za-z0-9_]*$")
scalar identifier extends string;

@pattern("^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
scalar documentationId extends string;

enum visibility {
  Public: "public",
  Private: "private",
}

enum stability {
  Experimental: "experimental",
  Stable: "stable",
  Deprecated: "deprecated",
}

enum behavior {
  Sync: "sync",
  Async: "async",
  Streaming: "streaming",
}

model interfaceSource {
  @pattern("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+-interfaces$")
  coordinate: string;

  @minLength(1)
  versionRequirement: string;

  schemaDialect: "https://json-schema.org/draft/2020-12/schema";
}

model package {
  @pattern("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
  coordinate: string;

  namespace: identifier;

  @minItems(1)
  interfaces: interfaceSource[];

  description?: string;
}

@oneOf
union typeRef {
  primitive: {
    kind: "primitive";

    @extension("enum", #["string", "boolean", "integer", "number", "bytes", "void", "unknown"])
    name: string;
  },

  named: {
    kind: "named";
    name: identifier;
  },

  collection: {
    @extension("enum", #["array", "optional"])
    kind: unknown;
    item: typeRef;
  },

  map: {
    kind: "map";
    key: typeRef;
    value: typeRef;
  },

  union: {
    kind: "union";

    @minItems(2)
    items: typeRef[];
  },

  generic: {
    kind: "generic";
    name: identifier;

    @minItems(1)
    arguments: typeRef[];
  },
}

model parameter {
  name: identifier;
  type: typeRef;
  description?: string;
  `default`?: unknown;
}

model auth {
  @extension("enum", #["none", "optional", "required"])
  mode: string;

  @uniqueItems
  @extension("items", #{type: "string", minLength: 1})
  schemes: string[];

  @uniqueItems
  @extension("items", #{type: "string", minLength: 1})
  scopes: string[];
}

@oneOf
union deprecation {
  current: null,
  deprecated: {
    @minLength(1)
    since: string;

    @minLength(1)
    message: string;

    @oneOf
    replacement?: documentationId | null;
  },
}

model callable {
  name: identifier;
  visibility: visibility;
  description?: string;
  parameters: parameter[];
  returns: typeRef;
  `async`: boolean;

  @extension("default", false)
  `static`?: boolean;

  throws?: typeRef[];
  behavior: behavior;
  auth: auth;
  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
}

model field {
  name: identifier;
  visibility: visibility;
  type: typeRef;

  @extension("default", false)
  readonly?: boolean;

  description?: string;
  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
}

model classSymbol {
  kind: "class";
  name: identifier;
  visibility: visibility;
  description?: string;
  fields: field[];
  constructors: callable[];
  methods: callable[];
  implements?: identifier[];
  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
}

model interfaceSymbol {
  kind: "interface";
  name: identifier;
  visibility: visibility;
  description?: string;
  methods: callable[];
  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
}

model functionSymbol {
  kind: "function";
  name: identifier;
  visibility: visibility;
  description?: string;
  parameters: parameter[];
  returns: typeRef;
  `async`: boolean;

  @extension("default", false)
  `static`?: boolean;

  throws?: typeRef[];
  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
  behavior: behavior;
  auth: auth;
}

model typeSymbol {
  kind: "type";
  name: identifier;
  visibility: visibility;
  description?: string;

  @oneOf
  definition:
    | { kind: "object"; fields: field[] }
    | { kind: "alias"; target: typeRef }
    | {
        kind: "enum";

        @minItems(1)
        values: identifier[];
      };

  documentationId: documentationId;
  stability: stability;
  deprecation: deprecation;
}

@oneOf
union symbol {
  class: classSymbol,
  interface: interfaceSymbol,
  function: functionSymbol,
  type: typeSymbol,
}
