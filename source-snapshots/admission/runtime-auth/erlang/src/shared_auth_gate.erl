%% Trusted admission code only; never call from a supervisor callback.
-module(shared_auth_gate).
-export([authorize/4, bearer/1, application_headers/1, evaluate/3]).

-type headers() :: [{binary(), binary()}].
-type decision() :: {ok, map()} | {error, invalid | forbidden | unavailable}.

%% Verify is trusted code, not tenant code. It receives only the token and policy.
%% Its result must originate from online, authenticated Shared Auth introspection.
-spec authorize(headers(), map(), fun((binary(), map()) -> term()), pos_integer()) -> decision().
authorize(Headers, Policy, Verify, Timeout) when is_integer(Timeout), Timeout > 0, Timeout =< 5000 ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case bearer(Headers) of
        {ok, Token} ->
            Parent = self(),
            Tag = make_ref(),
            {Pid, Monitor} = spawn_monitor(fun() ->
                Result = try Verify(Token, Policy) catch _:_ -> {error, unavailable} end,
                Parent ! {Tag, Result}
            end),
            receive
                {Tag, Result} ->
                    demonitor(Monitor, [flush]),
                    case {erlang:monotonic_time(millisecond) < Deadline, Result} of
                        {true, {ok, Claims}} -> evaluate(Claims, Policy, erlang:system_time(second));
                        {true, {error, invalid}} -> {error, invalid};
                        _ -> {error, unavailable}
                    end;
                {'DOWN', Monitor, process, Pid, _} -> {error, unavailable}
            after Timeout ->
                exit(Pid, kill),
                receive {'DOWN', Monitor, process, Pid, _} -> ok end,
                receive {Tag, _} -> ok after 0 -> ok end,
                {error, unavailable}
            end;
        Error -> Error
    end;
authorize(_, _, _, _) -> {error, unavailable}.

-spec bearer(headers()) -> {ok, binary()} | {error, invalid}.
bearer(Headers) ->
    try
        Values = [V || {K, V} <- Headers, lower(K) =:= <<"authorization">>],
        case Values of
            [Value] when is_binary(Value), byte_size(Value) =< 16391 ->
                case re:run(Value, <<"^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/-]+=*)\\z">>,
                            [{capture, [1], binary}]) of
                    {match, [Token]} -> {ok, Token};
                    _ -> {error, invalid}
                end;
            _ -> {error, invalid}
        end
    catch _:_ -> {error, invalid} end.

%% A deliberately small allowlist. Product-specific headers need explicit review.
%% Credentials and claimed identities must never enter a tenant invocation.
-spec application_headers(headers()) -> headers().
application_headers(Headers) ->
    Allowed = [<<"accept">>, <<"content-type">>, <<"content-encoding">>],
    [{lower(K), V} || {K, V} <- Headers, is_binary(K), is_binary(V),
                      lists:member(lower(K), Allowed)].

-spec evaluate(term(), map(), integer()) -> decision().
evaluate(Claims, Policy, Now) ->
    try evaluate_checked(Claims, Policy, Now)
    catch _:_ -> {error, unavailable} end.

evaluate_checked(#{<<"active">> := false}, _, _) -> {error, invalid};
evaluate_checked(Claims, Policy, Now) ->
    #{issuer := Issuer, audience := Audience, project := Project,
      realm := Realm, providers := Providers, required_scopes := Required,
      min_aal := MinAal} = Policy,
    true = lists:member(Realm, [customer, admin]),
    true = is_integer(MinAal) andalso MinAal >= 1,
    true = is_list(Providers) andalso Providers =/= [],
    true = is_list(Required),
    true = lists:all(fun nonempty/1, [Issuer, Audience, Project] ++ Providers ++ Required),
    #{<<"active">> := true, <<"iss">> := ActualIssuer, <<"aud">> := ActualAudience,
      <<"project">> := ActualProject, <<"provider">> := Provider,
      <<"sub">> := Subject, <<"sid">> := Session, <<"jti">> := Jti,
      <<"auth_epoch">> := Epoch, <<"exp">> := Exp, <<"nbf">> := Nbf,
      <<"iat">> := Iat, <<"aal">> := Aal, <<"scope">> := Scope,
      <<"cred">> := CredentialClass} = Claims,
    IdentityValid = ActualIssuer =:= Issuer andalso ActualAudience =:= Audience
        andalso ActualProject =:= Project andalso lists:member(Provider, Providers)
        andalso lists:all(fun nonempty/1, [Subject, Session, Jti])
        andalso is_integer(Epoch) andalso Epoch >= 0
        andalso is_integer(Exp) andalso is_integer(Nbf) andalso is_integer(Iat)
        andalso Nbf =< Now andalso Iat =< Now andalso Exp > Now,
    case IdentityValid of
        false -> {error, invalid};
        true ->
            Scopes = binary:split(Scope, <<" ">>, [global, trim_all]),
            Allowed = is_integer(Aal) andalso Aal >= MinAal
                andalso CredentialClass =:= null
                andalso lists:all(fun(S) -> lists:member(S, Scopes) end, Required),
            case Allowed of
                false -> {error, forbidden};
                true -> {ok, #{subject => Subject, session => Session, auth_epoch => Epoch,
                              realm => Realm, audience => Audience, project => Project,
                              expires_at => Exp, aal => Aal}}
            end
    end.

nonempty(Value) -> is_binary(Value) andalso byte_size(Value) > 0 andalso byte_size(Value) =< 512.
lower(Value) when is_binary(Value) -> list_to_binary(string:lowercase(binary_to_list(Value))).
