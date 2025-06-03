% Pragmatic file path library.
%
% File system API shouldn't be about what you can do, but what you shouldn't do.
%
% FIXME: Predicates should more often throw exceptions.
% FIXME: There is still TOCTOU race condition, it must use openat system call
% in some way.
%
% References:
%
%   * [Go Os.Root package](https://go.dev/blog/osroot)
%   * [TOCTOU attack](https://dominoweb.draco.res.ibm.com/reports/rc24572.pdf)
%
% Conecpturally there 3 levels for file system access:
%
%   * Policy
%   * Description – everything that you can do
%   * OS – actual system calls like open, openat, opendir etc.
%
% Two bottom ones define a mechanism – for a clear separation of it from the policy.

:- module(syspath, [
    path/2,
    path/3,
    fs/2,
    fss/2,
    default_policy/1,
    user_policy/2,
    policy/1,
    syspath/2
]).

:- use_module(library(lists)).
:- use_module(library(dcgs)).
:- use_module(library(dif)).
:- use_module(library(si)).

% Policy level %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% default_policy(+Policy) is det.
%
% Define this predicate to set a default policy for path/2. It must be
% deterministic, because it will be called once and default value will be used
% on failure.
%
% List of all policies: lax, ns, can, abs, np, np(_).
%
:- dynamic(default_policy/1).


%% user_policy(+Policy, ?Segments) is semidet.
%
% You are invited to write your own policies. You can use fs/2 predicate to
% reason about particular segment.
%
% Policy is any ground term (usually an atom). When you want to select your
% policy you must wrap it in user/1 functor. So for example if you define
% `user_policy(foo, _)` then you can use it as `path(user(foo), _, _)`.
%
% Also it is advisable to make this predicate semi-deterministic – it would be
% called only once internally anyway.
%
:- dynamic(user_policy/2).


%% policy(?Policy) is det.
%
% User can specify default policy by defining default_policy/1 predicate,
% otherwise np is used.
%
policy(P) :-
    catch((default_policy(U),ground(U)), _, false) ->
        must_be_policy(U, P)
    ;   must_be_policy(np, P).

must_be_policy(A, B) :-
    A = B -> true; throw(error(bad_policy(A,B),_)).


%% path(?Segments, ?SystemPath).
%
% Same as path/3, but uses the default policy. Example:
%
%     path(["/home/user",/,UserPath], S).
%
path(Segments, SystemPath) :-
    policy(P),
    path(P, Segments, SystemPath).

%% path(?Policy, ?Segments, ?SystemPath).
%
% SystemPath is a representation of Segments under the Policy. Segments is a
% list consisting of strings - representing any part of a path or special
% atoms: (/), dir, root, (.) and (..).
%
% It is never a good idea to use append/3 or other similar predicates to deal
% with system paths unless you want to invite vulnerabilities into your program.
% Just treat system path as an opaque string.
%
% lax policy doesn't specify any policy
path(lax, Segments, SystemPath) :-
    syspath(Segments, SystemPath).
% ns policy tells that path shouldn't contain spaces
path(ns, Segments, SystemPath) :-
    syspath(Segments, SystemPath), maplist(dif(' '), SystemPath).
% can policy tells that path must be canonical
path(can, Segments, SystemPath) :-
    syspath(Segments, SystemPath),
    realpath(SystemPath, SystemPath).
% abs policy tells that provided path must be absolute
path(abs, Segments, SystemPath) :-
    (   Segments = [root|_]
    ;   fs(abs_path, Segments)
    ),
    syspath(Segments, SystemPath).
% np policy tells that last segment must never escape from all previous segments
path(np, Segments, SystemPath) :-
   append(Root, [/,_], Segments),
   syspath(Segments, SystemPath),
   syspath(Root, SystemRootPath),
   realpath(SystemRootPath, CanonicalRoot),
   realpath(SystemPath, CanonicalFull),
   append(CanonicalRoot, _, CanonicalFull).

% user(_) is a user defined policy
path(user(Policy), Segments, SystemPath) :-
    syspath(Segments, SystemPath),
    term_si(Policy),
    once(user_policy(Policy, Segments)).


% Description level %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
:- discontiguous(fs/2).
:- multifile(fs/2).

%% syspath(?Segments, -SystemPath).
%
% SystemPath path is a concatenation of all Segments with additional rules to
% to handle special atoms.
%
% This predicate has a prefered direction from Segments to SystemPath, because
% of how much ambiguous file paths usually are.
%
syspath(A, S) :- phrase(syspath(A), S), segvalid(A).

segvalid([]).
segvalid([H|T]) :- follows(start, H), segvalid_(T, H).

segvalid_([], F) :- follows(F, end).
segvalid_([H|T], F) :- follows(F, H), segvalid_(T, H).

%% follows(+A, +B).
%
%  Defines when it is ok to A be followed by B.
follows(A, B) :- chars_si(A), chars_si(B).
follows((/), B) :- chars_si(B).
follows(A, (/)) :- chars_si(A).
follows(root, B) :- chars_si(B).
follows(A, dir) :- chars_si(A).
follows(A, end) :- chars_si(A).
follows(dir, end).
follows(root, end).
follows(start, root).
follows(start, B) :- chars_si(B).


syspath([]) --> "".
syspath([[]|S]) --> syspath(S).
syspath([L|S]) --> {L=[_|_]}, L, syspath(S).
syspath([/|S]) --> sep, syspath(S).
syspath([.|S]) --> sep, ".", sep, syspath(S).
syspath([..|S]) --> sep, "..", sep, syspath(S).
syspath([dir]) --> sep.
syspath([root|S]) --> sep, syspath(S).
sep --> "/".


%% fss(?Property, ?Segments) is multi.
%
% Segments together have a Property.
%
% FIXME: Not all properties are defined
%
fss(rel_path, [A,/|B]) :-
    fs(basename(good), A), maplist(fs(rel_path), B).


%% fs(?Property, ?Segment) is multi.
%
% Segment has a Property.
%
% Developers are invited to define their own properties and use them in own
% policies.
%
fs(empty_path, "").
fs(root_dir, "/").
fs(this_dir, ".").
fs(parent_dir, "..").
fs(file_like_basename, A) :-
    phrase((ns,nss), A);
    fs(empty_path, A).
fs(hidden, A) :- phrase((".",ns,nss,(ns|"/")), A).
fs(dir_like_basename, A) :- phrase((ns,nss,"/"), A).
fs(dir_like_abs_path, A) :- phrase(("/",[_],...), A).
fs(dir_like_rel_path, A) :- phrase((ns,...,"/",...), A).
fs(basename(good), S) :-
    fs(file_like_basename, S);
    fs(this_dir, S);
    fs(parent_dir, S).
fs(basename(bad), S) :- fs(root_dir, S).
fs(dirname, S) :-
    fs(this_dir, S);
    fs(parent_dir, S);
    fs(root_dir, S).
fs(rel_path, S) :-
    fs(basename(good), S);
    fs(dir_like_rel_path, S).
fs(abs_path, S) :-
    fs(dir_like_abs_path, S);
    fs(canonical_path, S).
fs(canonical_path, S) :-
    fs(root_dir, S).
fs(path, _).


nss --> [].
nss --> ns, nss.

ns --> {dif((/),C)}, [C].


% OS level %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% realpath(+Path, -CanonicalPath) is det.
%
% TODO: Check if it is equivalent to standard realpath(2) C library function.
%
realpath(Path, CanonicalPath) :-
    '$path_canonical'(Path, CanonicalPath) -> true; throw(error(bad_path(Path), _)).
