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

///
/// Used for debug purposes
///
fn print_array(my_array: &[u8])
{
	for x in my_array.iter()
	{
		print!("{:X},",x);
	}
}