use std::collections::HashMap;
use rand::Rng;
use sha2::{Digest, Sha384};


const INITIAL_MESSAGE: &str = "Подолянко Тимофій Олександрович";

const DEFAULT_ATTACK_RUN_COUNT: usize = 100;
const PRE_ATTACK_RUN_COUNT: usize = DEFAULT_ATTACK_RUN_COUNT;
const BD_ATTACK_RUN_COUNT: usize = DEFAULT_ATTACK_RUN_COUNT;


fn my_hash_16(bytes: &[u8]) -> [u8; 2] {
    Sha384::digest(bytes)[Sha384::output_size() - 2..Sha384::output_size()]
        .try_into()
        .expect("should take last two bytes of digest slice")
}

fn my_hash_32(bytes: &[u8]) -> [u8; 4] {
    Sha384::digest(bytes)[Sha384::output_size() - 4..Sha384::output_size()]
        .try_into()
        .expect("should take last four bytes of digest slice")
}

/// add a random natural number (u64) string to the message
fn transform_message_1(message: &str) -> String {
    let random: u64 = rand::thread_rng().gen();
    let random_string = random.to_string();
    let mut new_message = String::from(message);
    new_message.push_str(&random_string);

    new_message
}

/// replace a random character with a random ascii graphical character
fn transform_message_2(message: &str) -> String {
    // choose a random character index
    let index = rand::thread_rng().gen_range(0..message.chars().count());

    // choose a random replacement character
    let new_char = rand::thread_rng().gen_range('!'..='~');

    let mut new_message = String::from(message);
    let replace_char_index = new_message.char_indices()
        .nth(index)
        .expect("index less than message.chars().count()");

    new_message.replace_range(
        replace_char_index.0..(replace_char_index.0 + replace_char_index.1.len_utf8()),
        &new_char.to_string());

    new_message
}

fn pre_attack<T, F, H>(
    message: &str,
    mut transform_func: T,
    mut hash_func: F,
    incremental_transform: bool,
)
where
    T: FnMut(&str) -> String,
    F: FnMut(&[u8]) -> H,
    H: Eq,
{
    let target_hash = hash_func(message.as_bytes());
    let mut other_message: String;

    let mut last_message = message.to_owned();
    loop {
        if incremental_transform {
            other_message = transform_func(&last_message);
        } else {
            other_message = transform_func(message);
        }

        let other_hash = hash_func(other_message.as_bytes());

        if target_hash == other_hash { break; }
        if incremental_transform { last_message = other_message; }
    }

    println!("Collision: {other_message} :-: {message}");
}

fn bd_attack<T, F, H>(message: &str, mut transform_func: T, mut hash_func: F)
where
    T: FnMut(&str) -> String,
    F: FnMut(&[u8]) -> H,
    H: std::hash::Hash + Eq,
{
    let mut map: HashMap<H, String> = HashMap::new();

    let initial_hash = hash_func(message.as_bytes());
    map.insert(initial_hash, message.to_owned());

    loop {
        let new_message = transform_func(message);
        let new_message_hash = hash_func(new_message.as_bytes());

        if map.contains_key(&new_message_hash) {
            let collision = map.get_key_value(&new_message_hash)
                .expect("map.contains_key(&hash) was true");

            if collision.1 == message {
                // same message
                continue
            }

            println!("Collision: {new_message} :-: {collision}", collision=collision.1);
            break;
        }

        map.insert(new_message_hash, new_message);
    }
}

fn prepare_run_unique_message(prefix: &str) -> String {
    let mut per_run_init_message = String::from(prefix);
    per_run_init_message.push_str(INITIAL_MESSAGE);
    per_run_init_message.push(' ');

    let message_suffix: String = (0..rand::thread_rng()
        .gen_range(0..PRE_ATTACK_RUN_COUNT / 5))
        .map(|_| { rand::thread_rng().gen_range('!'..='~') })
        .filter(|c| { c.is_ascii_graphic() })
        .collect();

    per_run_init_message.push_str(&message_suffix);
    per_run_init_message
}

fn main() {
    for _ in 0..PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        println!("Initial message: {per_run_init_message}");
        pre_attack(&per_run_init_message, transform_message_1, my_hash_16, false);
    }

    for _ in 0..PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        println!("Initial message: {per_run_init_message}");
        pre_attack(&per_run_init_message, transform_message_2, my_hash_16, true);
    }

    for _ in 0..BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        println!("Initial message: {per_run_init_message}");
        bd_attack(&per_run_init_message, transform_message_1, my_hash_32);
    }

    for _ in 0..BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        println!("Initial message: {per_run_init_message}");
        bd_attack(&per_run_init_message, transform_message_2, my_hash_32);
    }
}