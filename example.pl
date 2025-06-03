:- use_module(syspath).

load_and_parse_file(UserPath, ParsedSomething) :-
    path(["/home/user",/,UserPath], S),
    parsed_something(S, ParsedSomething).

load_and_parse_file2(UserFile, ParsedSomething) :-
    path(lnd, ["/home/user",/,".config/myprog",/,UserFile], S),
    parsed_something(S, ParsedSomething).
