extern crate rustc_serialize;
use rustc_serialize::json::Json;

fn main() {
	let contents = "{\"pop\":123}";
	let data = Json::from_str(contents).unwrap();
	println!("{}",data.pretty());
}
