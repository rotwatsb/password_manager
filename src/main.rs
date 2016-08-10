extern crate password_manager;

use password_manager::Keychain;

fn main() {


    let mut kc: Keychain = Keychain::init("a8992333");

    kc.set("google.com".to_string(), "don'thurtme".to_string());
    kc.set("reddit.com".to_string(), "dothedeew".to_string());
    kc.set("planet.bop".to_string(), "dontstopmenow".to_string());
    //println!("{}", kc.get("whereuat.com".to_string()).unwrap());
    println!("{}", kc.get("google.com".to_string()).unwrap());
    println!("{}", kc.get("reddit.com".to_string()).unwrap());

    if let Some(x) = kc.get("yodog.com".to_string())
    { println!("{}", x); } else { println!("yodog not found"); }

    if let Some(x) = kc.get("planet.bop".to_string())
    { println!("{}", x); }

    let dump = kc.dump();
    println!("{}", dump);

    if let true = kc.remove("planet.bop".to_string())
    { println!("Success!"); } else { println!("Hmmm...") }

    if let true = kc.remove("planet.bo".to_string())
    { println!("Success!"); } else { println!("Hmmm...") }

    if let Some(x) = kc.get("planet.bop".to_string())
    { println!("{}", x); } else { println!("Bop not found"); }
    
    let dump2 = kc.dump();
    println!("{}", dump);

    if let Some(mut kc2) = Keychain::load("a8992333", dump2) {
        println!("{}", kc2.dump());
    }
    else {
        println!("Couldn't load passwords.");
    }
}
