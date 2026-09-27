import "@typespec/json-schema";
using TypeSpec.JsonSchema;

// Independently human-authored peer of auth-lifecycle-adapters.schema.json.
// Neither authority is generated from or allowed to overwrite the other.
@jsonSchema
namespace SharedAuthLifecycleAdapters;

enum adapterDelivery {
  ReactiveX: "reactivex",
  NativeStream: "native-stream",
  PromiseFuture: "promise-future",
  AsyncIterable: "async-iterable",
  Callback: "callback",
}

enum reactiveLibrary {
  None: "none",
  RxJS: "rxjs",
  RxDart: "rxdart",
}

enum lifecycleChannel {
  State: "state",
  Transition: "transition",
  AllowsAuthenticatedApi: "allows-authenticated-api",
  AllowsPrivilegedApi: "allows-privileged-api",
  OperationInFlight: "operation-in-flight",
}

model lifecycleAdapter {
  @pattern("^[a-z0-9][a-z0-9._-]*$")
  runtime: string;

  library: reactiveLibrary;

  @minItems(1)
  @uniqueItems
  delivery: adapterDelivery[];

  @minItems(2)
  @uniqueItems
  channels: lifecycleChannel[];

  replayCurrentState: boolean;
  boundedReplay: boolean;
  suppressDuplicateCapabilities: boolean;
  explicitRejectedTransitions: boolean;
  serialDispatch: boolean;
}

model lifecycleContract {
  schemaVersion: 1;

  @pattern("^[a-f0-9]{64}$")
  lifecycleFingerprint: string;

  @minItems(1)
  adapters: lifecycleAdapter[];
}
