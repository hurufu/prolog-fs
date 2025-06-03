:- use_module(syspath).

:- dynamic((?-)/1).
:- discontiguous((?-)/1).
:- multifile((?-)/1).
:- meta_predicate('?-'(0)).


runtests :-
    ?-(T), (T -> write('% PASS '); write('% FAIL ')), portray_clause(T).


% Empty path is valid, most FS will interpret it as a non-existen file
?- syspath([], "").

% Single segment is always a valid path
?- syspath(["/home/user"], "/home/user").
?- syspath(["abc/wee"], "abc/wee").
?- syspath(["single"], "single").
?- syspath(["un/exp/ected=?*&^%-"], "un/exp/ected=?*&^%-").
?- syspath(["-"], "-").

% Interesting special case when path ends with a folder separator
% So, single segment is valid system path, but if we want to construct it we
% can't use (/) atom, becuase it is *only* for separation and never to indicate
% that something is a folder. You should use special atom dir for this case.
?- syspath(["a/"], "a/").
?- \+ syspath(["a",/], _).
?- syspath(["a",dir], "a/").
?- \+ syspath(["a",dir,"b"], _).
?- \+ syspath([dir,"b"], _).
?- \+ syspath([dir], _).

% Path is separated by (/)
?- syspath(["a",/,"b"], "a/b").

% (/) is a separator – thus it can't be repeated
?- \+ syspath(["a",/,/], _).
% But if you want to you can do something like:
?- syspath(["a",/,"",/,""], "a//").
?- syspath(["",/,"",/,""], "//").

% Maybe counter intuitive, but you can define absolute path using / inside a
% segment, but you can't define root folder using (/) atom. You must use root
% atom instead.
?- syspath(["/"], "/").
?- syspath(["/a"], "/a").
?- \+ syspath([/,"a"], _).
?- \+ syspath([/], _).
?- syspath([root], "/").
?- syspath([root,"a"], "/a").
?- \+ syspath([root,/], _).
?- \+ syspath([root,/,"a"], _).
?- \+ syspath(["a",root], _).
?- \+ syspath([root,root], _).
?- \+ syspath([root,dir], _).
?- \+ syspath([dir,root], _).

% Concatenation is allowed
?- syspath(["00-","imgbase"], "00-imgbase").


