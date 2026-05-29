# Prototype of a pragmatic FS predicates for Prolog

Way to many programmers (even experienced ones) think that file system paths
are strings – they are not (maybe on some basic level only). It is much
better to think about file paths as opaque OS specific objects that don't have
exact meaning unless OS does full path traversal and dereferences it to a
file descriptor and loose precise meaning when file descriptor was closed.

If you fail to accept this notion I would not trust your software. It most
probably is vulnerable to a vast array of file path traversal attacks.

If you are still skeptical, just answer a question: given prefix `A`, stem
`B` and `append(A,B,C)`, does `C` *always* be inside a prefix `A`? What if
`B = "/../../../../../../etc/passwd"`? That's why you should *never* treat paths
as strings for concatenation.

This project is just a prototype, don't expect any documentation or explanations
any time soon.
