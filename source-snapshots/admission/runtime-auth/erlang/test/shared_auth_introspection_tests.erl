-module(shared_auth_introspection_tests).
-include_lib("eunit/include/eunit.hrl").

transport_test_() ->
    {setup,
     fun() ->
         {ok, _} = application:ensure_all_started(inets),
         {ok, Pid} = inets:start(httpc, [{profile, auth_fixture}]),
         Pid
     end,
     fun(Pid) -> inets:stop(httpc, Pid) end,
     fun(_) ->
         [?_assertEqual({error, invalid}, exchange(200, <<"{\"active\":false}">>)),
          ?_assertEqual({ok, #{<<"active">> => true}}, exchange(200, <<"{\"active\":true}">>)),
          ?_assertEqual({error, unavailable}, exchange(200, <<"{}">>)),
          ?_assertEqual({error, unavailable}, exchange(200, <<"not-json">>)),
          ?_assertEqual({error, unavailable}, exchange(503, <<>>)),
          ?_assertEqual({error, unavailable}, exchange(302, <<>>))]
     end}.

exchange(Status, Body) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {packet, http_bin},
                                     {ip, {127, 0, 0, 1}}]),
    {ok, {_, Port}} = inet:sockname(Listen),
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        {ok, Socket} = gen_tcp:accept(Listen, 2000),
        {ok, {http_request, 'POST', {abs_path, <<"/auth/introspect">>}, _}} = gen_tcp:recv(Socket, 0, 2000),
        Length = read_headers(Socket, 0),
        ok = inet:setopts(Socket, [{packet, raw}]),
        {ok, Payload} = gen_tcp:recv(Socket, Length, 2000),
        #{<<"contract">> := <<"IntrospectionRequest">>,
          <<"payload">> := #{<<"token">> := <<"fixture-token">>,
                            <<"audience">> := <<"fixture-api">>,
                            <<"requiredScopes">> := [<<"invoke">>]}} = json:decode(Payload),
        ok = gen_tcp:send(Socket, ["HTTP/1.1 ", integer_to_list(Status), " Fixture\r\n",
            "Content-Type: application/json\r\nContent-Length: ", integer_to_list(byte_size(Body)),
            "\r\nConnection: close\r\n\r\n", Body]),
        gen_tcp:close(Socket),
        Parent ! {self(), checked}
    end),
    Result = shared_auth_introspection:verify(<<"fixture-token">>,
        #{audience => <<"fixture-api">>, required_scopes => [<<"invoke">>]},
        #{port => Port, profile => auth_fixture, service_credential => binary:copy(<<"f">>, 32)}),
    gen_tcp:close(Listen),
    receive
        {Pid, checked} -> demonitor(Ref, [flush]);
        {'DOWN', Ref, process, Pid, Reason} -> error({fixture_failed, Reason})
    after 2500 -> exit(Pid, kill), error(fixture_timeout)
    end,
    Result.

read_headers(Socket, Length) ->
    case gen_tcp:recv(Socket, 0, 2000) of
        {ok, {http_header, _, 'Content-Length', _, Value}} -> read_headers(Socket, binary_to_integer(Value));
        {ok, {http_header, _, _, _, _}} -> read_headers(Socket, Length);
        {ok, http_eoh} -> Length
    end.
