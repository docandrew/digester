# digester
Rust version of hashing algorithms

This was an attempt to learn Rust by porting some basic hashing algorithms from the RFC reference C code.
I only got as far as porting SHA-1, didn't get around to the more modern SHA algorithms. One interesting
thing I learned was that Rust debug mode panics on overflow arithmetic, where SHA-1 relies on this
behavior. Compiling with Release mode fixes this, but use of wrapping functions like wrapping_add() was
added later to be more proper. 

https://doc.rust-lang.org/std/num/struct.Wrapping.html

This looks a lot like the C reference code and is probably not the "Rust" way of doing things!
