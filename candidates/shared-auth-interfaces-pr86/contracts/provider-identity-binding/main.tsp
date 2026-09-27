import "@typespec/json-schema";
using TypeSpec.JsonSchema;

// Independent peer of authored.schema.json. Neither authority is generated
// from or allowed to overwrite the other.
@jsonSchema
namespace SharedAuth.ProviderIdentityBinding;

@id("ProviderIdentityKey")
model ProviderIdentityKey {
  @minLength(1)
  @maxLength(64)
  @pattern("^[a-z][a-z0-9:_-]{0,63}$")
  provider: string;

  @minLength(8)
  @maxLength(2048)
  @pattern("^https://")
  issuer: string;

  @minLength(1)
  @maxLength(512)
  subject: string;

  @minLength(1)
  @maxLength(64)
  @pattern("^[a-z][a-z0-9:_-]{0,63}$")
  realm: string;
}

@id("LegacyIdentityReference")
model LegacyIdentityReference {
  @minLength(1)
  @maxLength(255)
  principal_id?: string;

  @minLength(1)
  @maxLength(255)
  provider_tenant?: string;

  @minLength(1)
  @maxLength(512)
  provider_subject?: string;

  migration_state: "not_required" | "mapped" | "quarantined";
  migration_basis: "canonical_tuple" | "reviewed_provider_mapping" | "fresh_reverification" | "insufficient_evidence";
}

@id("ProviderIdentityBinding")
model ProviderIdentityBinding {
  schema_version: 1;
  key: ProviderIdentityKey;

  @minLength(1)
  @maxLength(255)
  shared_user_id: string;

  status: "active" | "revoked";
  legacy?: LegacyIdentityReference;
}

@id("IdentityNonMergeScenario")
model IdentityNonMergeScenario {
  schema_version: 1;
  left: ProviderIdentityBinding;
  right: ProviderIdentityBinding;

  @minLength(3)
  @maxLength(320)
  matching_profile_email: string;

  email_is_identity_evidence: false;
  expected_same_identity: false;
}
