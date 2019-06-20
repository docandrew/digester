use std::env;
use std::convert::AsRef;
use std::io;
use std::io::Error;
use std::io::BufReader;
use std::process;
use std::io::prelude::*;
use std::fs::File;
use std::fs::metadata;
use std::i32;

fn main()
{
    let args: Vec<_> = env::args().collect();

    if args.len() < 3 
    {
    	print_usage_and_exit();
    }

    let hash_type = args[1].to_uppercase();
    let ref in_filename = args[2];

    match hash_type.as_ref() 
    {
    	//"MD5" => md5(in_filename),
    	"SHA1" => sha1(in_filename),
    	"SHA256" => sha256(in_filename),
    	"SHA224" => sha224(in_filename),
    	"SHA384" => sha384(in_filename),
    	"SHA512" => sha512(in_filename),
    	"SHA512_224" => sha512_224(in_filename),
    	"SHA512_256" => sha512_256(in_filename),
    	"SHA3" => sha3(in_filename),
    	_ => print_usage_and_exit(),
	}
}

fn print_usage_and_exit()
{
  	println!(" Usage: digester [HASHTYPE] filename");
	println!("  where HASHTYPE is one of: MD5, SHA1, SHA256, SHA224, SHA384, SHA512, SHA512_224, SHA512_256, SHA3");
	process::exit(1);
}

/// Calculates the MD5 message digest (hash) for a given file
/// Note: relies on overflow arithmetic, so must be compiled in RELEASE mode.
///
/// WARNING: MD5 is no longer recognized as a suitable hashing algorithm.
///          It is included here for completion. It may be suitable as a
///          checksum algorithm to ensure data integrity against accidental
///          file corruption.
/// 
// fn md5(in_filename : &str)
// {
// 	println!( "Calculating MD5 digest for {}", in_filename);
// 	match run_md5(in_filename)
// 	{
// 		Ok(s) => print!(""),
// 		Err(e) => println!(" Error: {}", e.to_string());
// 	}

fn run_sha1(in_filename : &str) -> io::Result<String>
{
	//Ok("Hash value: ".to_string())
	Ok("Done.".to_string())
}

/// Calculates the SHA1 message digest (hash) for a given file
/// Note: relies on overflow arithmetic, so must be compiled in RELEASE mode.
///       Rust debug mode will panic on arithmetic overflow which is an
///       essential part of this hashing algorithm.
/// 
/// See FIPS 180-1 and RFC3174 for details.
///
/// 
fn sha1(in_filename : &str)
{
	match run_sha1(in_filename)
	{
		Ok(s) => print!(""),
		Err(e) => println!(" Error: {}", e.to_string()),
	}

	fn run_sha1(in_filename : &str) -> io::Result<String>
	{
		//let max_message_size_bits = 64;
		//let block_size_bits = 512;
		//let word_size_bits = 32;

		//intermediate hash values, initialized to starting values
		let mut intermediate_hash : [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]; 

		//println!( "Calculating SHA1 digest for {}", in_filename);

	    let mut in_file = try!(File::open(in_filename));

	    let metadata = try!(metadata(in_filename));
	    let file_size = metadata.len();

	    //println!(" file size: {}", file_size);

	    //let mut reader = &mut BufReader::new(in_file);

	    let mut done = false;

	    //SHA1 algorithm vars
	    //let mut message_schedule : [u32; 32] = [0; 32]; 

	    //modulus addition;
	    //(a + b) % b

	    while !done
	    {
		    let mut message_block : [u8; 64] = [0; 64];
		    let mut block_bytes_read : usize = 0;
			let mut message_block_index : usize; 	//used for padding
		    
		    //take at most 64 bytes (16 32-bit words, 512 bits) for block
		    block_bytes_read = in_file.read(&mut message_block).unwrap();

		    //let mut chunk = reader.take(64);
		    //let status = chunk.read_to_end(&mut message_block);

		    //match status 
		    //{
		    //	Ok(n) => block_bytes_read = n,
		    //	_ => (),
		    //}

		    //println!(" read {} byte message block: ", block_bytes_read);
		    //print_array(&message_block);
		    //println!("");

		    //Process message block
		    if block_bytes_read == 64
		    {
		    	//println!("aa");
		    	process_sha1_block(&mut message_block, &mut intermediate_hash);
		    }
			else 
			{
				//println!("a");
				message_block_index = block_bytes_read;
				//pad message (same padding used for SHA-1, SHA-224, SHA-256)
				// if current message block is too small to hold the padding bits and length,
				// pad the block, process it and continue padding into a second block.
				if message_block_index > 55
				{
					//println!("b");
					message_block[message_block_index] = 0x80;
					message_block_index += 1;

					while message_block_index < 64
					{
						message_block[message_block_index] = 0;
						message_block_index += 1;
					}

					process_sha1_block(&mut message_block, &mut intermediate_hash);

					//zero out the entire block so we can append the length and then process it
					message_block_index = 0;

					while message_block_index < 56
					{
						message_block[message_block_index] = 0;
						message_block_index += 1;
					}
				}
				else 
				{
					//println!("c");
					message_block[message_block_index] = 0x80;
					message_block_index += 1;

					while message_block_index < 56 
					{
						message_block[message_block_index] = 0;
						message_block_index += 1;
					}
				}

				//store message length (in bits) as last 8 bytes
				let message_size_bits : u64 = file_size * 8;

				message_block[56] = ((message_size_bits & 0xFF00_0000_0000_0000) >> 56) as u8;
				message_block[57] = ((message_size_bits & 0x00FF_0000_0000_0000) >> 48) as u8;
				message_block[58] = ((message_size_bits & 0x0000_FF00_0000_0000) >> 40) as u8;
				message_block[59] = ((message_size_bits & 0x0000_00FF_0000_0000) >> 32) as u8;
				message_block[60] = ((message_size_bits & 0x0000_0000_FF00_0000) >> 24) as u8;
				message_block[61] = ((message_size_bits & 0x0000_0000_00FF_0000) >> 16) as u8;
				message_block[62] = ((message_size_bits & 0x0000_0000_0000_FF00) >> 8) as u8;
				message_block[63] = (message_size_bits & 0x0000_0000_0000_00FF) as u8;

				process_sha1_block(&mut message_block, &mut intermediate_hash);

				done = true;
				break;
			}

		    fn process_sha1_block(message_block : & [u8], intermediate_hash : &mut [u32])
		    {
		    	//print!(" Processing msg block: ");
		    	//print_array(&message_block);
		    	//println!("");

		    	//SHA-1 constants
			    let k : [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
			    //let mut t : i32;					//loop counter
			    let mut temp : u32;					//temporary word value
			    let mut w : [u32; 80] = [0; 80];	//word sequence
			    let mut a : u32;					//word buffers
			    let mut b : u32;
			    let mut c : u32;
			    let mut d : u32;
			    let mut e : u32;

			    //initialize first 16 words in array w
			    for t in 0 .. 16
			    {
			    	w[t] = (message_block[t * 4] as u32) << 24;
			    	w[t] |= (message_block[t * 4 + 1] as u32) << 16;
			    	w[t] |= (message_block[t * 4 + 2] as u32) << 8;
			    	w[t] |= message_block[t * 4 + 3] as u32;
			    }

			    for t in 16 .. 80
			    {
			    	w[t] = rotl(w[t-3] ^ w[t-8] ^ w[t - 14] ^ w[t - 16], 1);
			    }

			    //intialize five working variables a,b,c,d,e with the (i-1)st hash value
			    a = intermediate_hash[0];
			    b = intermediate_hash[1];
			    c = intermediate_hash[2];
			    d = intermediate_hash[3];
			    e = intermediate_hash[4];

			    for t in 0 .. 20
			    {
			    	//println!("a: {:X}, b: {:X}, c: {:X}, d: {:X}, e: {:X}, w[t]: {}, k[0]: {:X}", a,b,c,d,e,w[t],k[0]);
					temp = rotl(a,5).wrapping_add( ((b & c) | ((!b) & d)) ).wrapping_add(e).wrapping_add(w[t]).wrapping_add(k[0]);

			    	e = d;
			    	d = c;
			    	c = rotl(b,30);
			    	b = a;
			    	a = temp;
			    }

			    for t in 20 .. 40
			    {
					temp = rotl(a,5).wrapping_add((b ^ c ^ d)).wrapping_add(e).wrapping_add(w[t]).wrapping_add(k[1]);

			    	e = d;
			    	d = c;
			    	c = rotl(b,30);
			    	b = a;
			    	a = temp;
			    }

			    for t in 40 .. 60
			    {
					temp = rotl(a,5).wrapping_add(((b & c) | (b & d) | (c & d))).wrapping_add(e).wrapping_add(w[t]).wrapping_add(k[2]);

			    	e = d;
			    	d = c;
			    	c = rotl(b,30);
			    	b = a;
			    	a = temp;
			    }

			    for t in 60 .. 80
			    {
					temp = rotl(a,5).wrapping_add((b ^ c ^ d)).wrapping_add(e).wrapping_add(w[t]).wrapping_add(k[3]);

			    	e = d;
			    	d = c;
			    	c = rotl(b,30);
			    	b = a;
			    	a = temp;
			    }

			    //compute ith intermediate hash values
				(*intermediate_hash)[0] = (*intermediate_hash)[0].wrapping_add(a);
				(*intermediate_hash)[1] = (*intermediate_hash)[1].wrapping_add(b);
			    (*intermediate_hash)[2] = (*intermediate_hash)[2].wrapping_add(c);
			    (*intermediate_hash)[3] = (*intermediate_hash)[3].wrapping_add(d);
			    (*intermediate_hash)[4] = (*intermediate_hash)[4].wrapping_add(e);
			}
		}

	    //Ok("Hash value: ".to_string())
	    print!("{:X} ", intermediate_hash[0]);
	    print!("{:X} ", intermediate_hash[1]);
	    print!("{:X} ", intermediate_hash[2]);
	    print!("{:X} ", intermediate_hash[3]);
	    println!("{:X}", intermediate_hash[4]);
	    
		Ok("Done.".to_string())
	}
}

fn print_array(my_array: &[u8])
{
	for x in my_array.iter()
	{
		print!("{:X},",x);
	}
}

///
/// Circular left shift
///
fn rotl(word : u32, numbits : u32) -> u32
{
	assert!(numbits < 32);
	(word << numbits) | (word >> (32 - numbits))
}

///
/// Circular right shift
///
fn rotr(word : u32, numbits : u32) -> u32
{
	assert!(numbits < 32);
	(word >> numbits) | (word << (32 - numbits))
}
/*
//sha-224/256 constants
let k_256 : [u32 ; 64] =   [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
							0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
					        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
					        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
					        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
					        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
					        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
					        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
					        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
*/
fn ch(x : u32, y : u32, z : u32) -> u32
{
	((x & y) ^ ((!x) & z))
}

fn maj(x : u32, y : u32, z : u32) -> u32
{
	((x & y) ^ (x & z) ^ (y & z))
}					        

fn bsig0(x : u32) -> u32
{
	(rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
}

fn bsig1(x : u32) -> u32
{
	(rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) 
}

// fn ssig0(x : u32) -> u32
// {
// 	(rotr(x, 7) ^ )
// }

fn sha224(in_filename : &str)
{
	//let max_message_size_bits = 64; 
}

fn sha256(in_filename : &str)
{
	//let max_message_size_bits = 64;

}
/*
//sha-384, sha-512, sha-512/224 & sha-512/256 constants
let k_512 : [u64 ; 80] =   [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
							0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
							0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
							0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
							0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
							0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
							0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
							0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
							0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
							0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
							0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
							0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
							0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
							0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
							0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
							0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
							0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
							0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
							0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
							0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];
*/
fn sha384(in_filename : &str)
{
	//let max_message_size_bits = 128;
	//let block_size = 512;
	//let word_size = 32;
}

fn sha512(in_filename : &str)
{
	//let max_message_size_bits = 128;

}

fn sha512_224(in_filename : &str)
{
	//let max_message_size_bits = 128;

}

fn sha512_256(in_filename : &str)
{
	//let max_message_size_bits = 128;

}

fn sha3(in_filename : &str)
{

}