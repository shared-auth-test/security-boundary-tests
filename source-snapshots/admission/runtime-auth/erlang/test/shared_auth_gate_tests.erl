-module(shared_auth_gate_tests).
-include_lib("eunit/include/eunit.hrl").

policy() -> #{issuer => <<"https://auth.fixture.invalid">>, audience => <<"fixture-api">>,
              project => <<"fixture-project">>, realm => customer, providers => [<<"local">>],
              required_scopes => [<<"invoke">>], min_aal => 2}.
claims() -> #{<<"active">> => true, <<"iss">> => <<"https://auth.fixture.invalid">>,
              <<"aud">> => <<"fixture-api">>, <<"project">> => <<"fixture-project">>,
              <<"provider">> => <<"local">>, <<"sub">> => <<"canonical-user">>,
              <<"sid">> => <<"session">>, <<"jti">> => <<"token-id">>, <<"auth_epoch">> => 2,
              <<"exp">> => 200, <<"iat">> => 90, <<"nbf">> => 90, <<"aal">> => 2,
              <<"scope">> => <<"invoke read">>, <<"cred">> => null}.

bearer_test_() ->
    Bad = [[], [{<<"Authorization">>, <<"Bearer a">>}, {<<"authorization">>, <<"Bearer b">>}],
           [{<<"authorization">>, <<"Bearer a, Bearer b">>}],
           [{<<"authorization">>, <<"Bearer a\r\nx-auth-user-id: forged">>}],
           [{<<"authorization">>, <<"Bearer ">>}],
           [{<<"authorization">>, <<"Bearer a b">>}],
           [{<<"authorization">>, <<"Bearer ", (binary:copy(<<"a">>, 16385))/binary>>}]],
    [?_assertEqual({error, invalid}, shared_auth_gate:bearer(H)) || H <- Bad] ++
    [?_assertEqual({ok, <<"abc.def">>}, shared_auth_gate:bearer([{<<"AUTHORIZATION">>, <<"bEaReR abc.def">>}]))].

strip_test() ->
    ?assertEqual([{<<"content-type">>, <<"application/json">>}],
        shared_auth_gate:application_headers([{<<"X-Auth-User-Id">>, <<"forged">>},
            {<<"X-Shared-Auth-Proof">>, <<"forged">>}, {<<"cookie">>, <<"secret">>},
            {<<"authorization">>, <<"Bearer secret">>}, {<<"Content-Type">>, <<"application/json">>}])).

binding_test_() ->
    Changes = [{<<"iss">>, <<"https://evil.invalid">>}, {<<"aud">>, <<"other-api">>},
        {<<"project">>, <<"other-project">>}, {<<"provider">>, <<"unknown">>},
        {<<"exp">>, 100}, {<<"nbf">>, 101}, {<<"iat">>, 101}, {<<"sid">>, <<>>},
        {<<"auth_epoch">>, -1}, {<<"active">>, false}],
    [?_assertEqual({error, invalid}, shared_auth_gate:evaluate((claims())#{K => V}, policy(), 100))
        || {K, V} <- Changes].

authorization_test_() ->
    [?_assertEqual({error, forbidden}, shared_auth_gate:evaluate((claims())#{K => V}, policy(), 100))
        || {K, V} <- [{<<"aal">>, 1}, {<<"scope">>, <<"read">>}, {<<"cred">>, <<"sandbox">>}]].

principal_test() ->
    {ok, Principal} = shared_auth_gate:evaluate(claims(), policy(), 100),
    ?assertEqual(<<"canonical-user">>, maps:get(subject, Principal)),
    ?assertNot(maps:is_key(roles, Principal)),
    ?assertNot(maps:is_key(token, Principal)).

malformed_test_() ->
    [?_assertEqual({error, unavailable}, shared_auth_gate:evaluate(C, policy(), 100))
        || C <- [#{}, null, #{<<"active">> => <<"true">>}, maps:remove(<<"sid">>, claims()),
                 maps:remove(<<"cred">>, claims())]].

queued_result_after_deadline_test() ->
    Test = self(),
    {Caller, Monitor} = spawn_monitor(fun() ->
        Verify = fun(_, _) ->
            Test ! {verifier_ready, self()},
            receive continue -> ok end,
            Now = erlang:system_time(second),
            {ok, (claims())#{<<"exp">> => Now + 60, <<"iat">> => Now, <<"nbf">> => Now}}
        end,
        Result = shared_auth_gate:authorize(
            [{<<"authorization">>, <<"Bearer fixture">>}], policy(), Verify, 20),
        Test ! {decision, Result}
    end),
    receive
        {verifier_ready, Worker} ->
            true = erlang:suspend_process(Caller),
            try
                Worker ! continue,
                receive after 50 -> ok end
            after erlang:resume_process(Caller) end
    after 1000 -> error(verifier_not_started)
    end,
    receive {decision, Decision} -> ?assertEqual({error, unavailable}, Decision)
    after 1000 -> error(missing_decision) end,
    receive {'DOWN', Monitor, process, Caller, normal} -> ok
    after 1000 -> error(caller_not_finished) end.

deadline_test() ->
    Headers = [{<<"authorization">>, <<"Bearer fixture">>}],
    Slow = fun(_, _) -> receive after 500 -> {ok, claims()} end end,
    ?assertEqual({error, unavailable}, shared_auth_gate:authorize(Headers, policy(), Slow, 10)),
    ?assertEqual({messages, []}, process_info(self(), messages)).

crash_test() ->
    Crash = fun(_, _) -> error(fixture_failure) end,
    ?assertEqual({error, unavailable}, shared_auth_gate:authorize(
        [{<<"authorization">>, <<"Bearer fixture">>}], policy(), Crash, 100)).

missing_never_calls_verifier_test() ->
    Verify = fun(_, _) -> self() ! unexpected, {ok, claims()} end,
    ?assertEqual({error, invalid}, shared_auth_gate:authorize([], policy(), Verify, 100)).
