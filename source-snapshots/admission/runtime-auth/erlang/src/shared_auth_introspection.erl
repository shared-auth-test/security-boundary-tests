%% OTP 27+ (native json). Start a dedicated inets httpc profile at application boot.
-module(shared_auth_introspection).
-export([verify/3]).

%% Endpoint is intentionally loopback-only. A per-realm authenticated tunnel or
%% local Shared Auth server owns upstream TLS and authoritative session storage.
%% Policy and service credential MUST come from trusted deployment configuration.
-spec verify(binary(), map(), map()) -> {ok, map()} | {error, invalid | unavailable}.
verify(Token, Policy, #{port := Port, service_credential := Secret, profile := Profile})
        when is_integer(Port), Port > 0, Port =< 65535, is_binary(Secret), byte_size(Secret) >= 32 ->
    try
        nomatch = re:run(Secret, <<"[\\r\\n]">>),
        Body = iolist_to_binary(json:encode(#{
            <<"contract">> => <<"IntrospectionRequest">>,
            <<"payload">> => #{<<"token">> => Token, <<"audience">> => maps:get(audience, Policy),
                               <<"requiredScopes">> => maps:get(required_scopes, Policy)}
        })),
        Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/auth/introspect",
        Headers = [{"authorization", "Bearer " ++ binary_to_list(Secret)},
                   {"accept", "application/json"}],
        Options = [{timeout, 900}, {connect_timeout, 200}, {autoredirect, false}],
        case httpc:request(post, {Url, Headers, "application/json", Body}, Options,
                           [{body_format, binary}], Profile) of
            {ok, {{_, 200, _}, _, Response}} when byte_size(Response) =< 65536 ->
                case json:decode(Response) of
                    #{<<"active">> := true} = Claims -> {ok, Claims};
                    #{<<"active">> := false} -> {error, invalid};
                    _ -> {error, unavailable}
                end;
            _ -> {error, unavailable}
        end
    catch _:_ -> {error, unavailable} end;
verify(_, _, _) -> {error, unavailable}.
