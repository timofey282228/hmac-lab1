use crate::message_gen::{
    MessaageGenerator, NaturalNumberMessageGenerator, RandomChangeMessageGenerator,
};
use rand::Rng;
use sha2::{Digest, Sha384};
use std::collections::HashMap;

mod message_gen;

const INITIAL_MESSAGE: &str = "Подолянко Тимофій Олександрович";

const DEFAULT_ATTACK_RUN_COUNT: usize = 100;
const PRE_ATTACK_RUN_COUNT: usize = DEFAULT_ATTACK_RUN_COUNT;
const BD_ATTACK_RUN_COUNT: usize = DEFAULT_ATTACK_RUN_COUNT;

/// quantile value for 99.5% confidence interval of mean
const QUANTILE_0995: f64 = 2.576;

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

fn pre_attack<F, H>(
    message: &str,
    mut message_generator: impl MessaageGenerator,
    hash_func: F,
    incremental_transform: bool,
) -> AttackStats
where
    F: Fn(&[u8]) -> H,
    H: Eq,
{
    let target_hash = hash_func(message.as_bytes());
    let mut other_message: String;
    let mut attack_stats = AttackStats::default();

    let mut last_message = message.to_owned();
    loop {
        if incremental_transform {
            other_message = message_generator.generate_from(&last_message);
        } else {
            other_message = message_generator.generate_from(message);
        }

        attack_stats.generated_messages_count += 1;

        let other_hash = hash_func(other_message.as_bytes());

        if target_hash == other_hash && message != other_message {
            break;
        }
        if incremental_transform {
            last_message = other_message;
        }
    }

    println!("Collision: {other_message} :-: {message}");
    attack_stats
}

fn bd_attack<F, H>(
    message: &str,
    mut message_generator: impl MessaageGenerator,
    hash_func: F,
    incremental_transform: bool,
) -> AttackStats
where
    F: Fn(&[u8]) -> H,
    H: std::hash::Hash + Eq,
{
    let mut map: HashMap<H, String> = HashMap::new();
    let mut attack_stats = AttackStats::default();
    let initial_hash = hash_func(message.as_bytes());
    let mut last_message = message.to_owned();

    map.insert(initial_hash, message.to_owned());

    loop {
        let new_message: String;
        if incremental_transform {
            new_message = message_generator.generate_from(&last_message);
        } else {
            new_message = message_generator.generate_from(message);
        }

        attack_stats.generated_messages_count += 1;
        let new_message_hash = hash_func(new_message.as_bytes());

        if map.contains_key(&new_message_hash) {
            let collision = map
                .get_key_value(&new_message_hash)
                .expect("map.contains_key(&hash) was true");

            if collision.1 == &new_message {
                // same message, not a collision
                if incremental_transform {
                    last_message = new_message.to_owned();
                }

                continue;
            }

            println!(
                "Collision: {new_message} :-: {collision}",
                collision = collision.1
            );
            break;
        }

        if incremental_transform {
            last_message = new_message.to_owned();
        }

        map.insert(new_message_hash, new_message);
    }

    attack_stats
}

fn prepare_run_unique_message(prefix: &str) -> String {
    let mut per_run_init_message = String::from(prefix);
    per_run_init_message.push_str(INITIAL_MESSAGE);
    per_run_init_message.push(' ');

    let message_suffix: String = (0..rand::thread_rng().gen_range(0..PRE_ATTACK_RUN_COUNT / 5))
        .map(|_| rand::thread_rng().gen_range('!'..='~'))
        .filter(|c| c.is_ascii_graphic())
        .collect();

    per_run_init_message.push_str(&message_suffix);
    per_run_init_message
}

fn main() {
    let mut cas_pre_1 = CumulativeAttackStats::default();
    for _ in 0..PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        println!("Initial message: {per_run_init_message}");
        let attack_stats = pre_attack(
            &per_run_init_message,
            NaturalNumberMessageGenerator::default(),
            my_hash_16,
            false,
        );

        cas_pre_1.include_attack(&attack_stats);
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_pre_1.average(),
        var = cas_pre_1.variance(),
        int = cas_pre_1.confidence_interval()
    );

    let mut cas_pre_2 = CumulativeAttackStats::default();
    for _ in 0..PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        println!("Initial message: {per_run_init_message}");
        let attack_stats = pre_attack(
            &per_run_init_message,
            RandomChangeMessageGenerator::default(),
            my_hash_16,
            true,
        );

        cas_pre_2.include_attack(&attack_stats);
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_pre_2.average(),
        var = cas_pre_2.variance(),
        int = cas_pre_2.confidence_interval()
    );

    let mut cas_bd_1 = CumulativeAttackStats::default();
    for _ in 0..BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        println!("Initial message: {per_run_init_message}");
        let attack_stats = bd_attack(
            &per_run_init_message,
            NaturalNumberMessageGenerator::default(),
            my_hash_32,
            false,
        );
        cas_bd_1.include_attack(&attack_stats);
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_bd_1.average(),
        var = cas_bd_1.variance(),
        int = cas_bd_1.confidence_interval()
    );

    let mut cas_bd_2 = CumulativeAttackStats::default();
    for _ in 0..BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        println!("Initial message: {per_run_init_message}");
        let attack_stats = bd_attack(
            &per_run_init_message,
            RandomChangeMessageGenerator::default(),
            my_hash_32,
            true,
        );
        cas_bd_2.include_attack(&attack_stats);
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_bd_2.average(),
        var = cas_bd_2.variance(),
        int = cas_bd_2.confidence_interval()
    );
}

struct AttackStats {
    generated_messages_count: u64,
}

struct CumulativeAttackStats {
    sum: u64,
    squares_sum: u64,
    count: u64,
}

impl CumulativeAttackStats {
    fn include_attack(&mut self, attack: &AttackStats) {
        self.sum += attack.generated_messages_count;
        self.squares_sum += attack.generated_messages_count.pow(2);
        self.count += 1;
    }

    fn average(&self) -> f64 {
        self.sum as f64 / self.count as f64
    }

    fn variance(&self) -> f64 {
        (self.squares_sum as f64 / self.count as f64)
            - (self.sum as f64 / self.count as f64).powi(2)
    }

    fn confidence_interval(&self) -> (f64, f64) {
        let average = self.average();
        let delta = (self.variance().sqrt() / (self.count as f64).sqrt()) * QUANTILE_0995;
        (average - delta, average + delta)
    }
}

impl Default for AttackStats {
    fn default() -> Self {
        Self {
            generated_messages_count: 0,
        }
    }
}

impl Default for CumulativeAttackStats {
    fn default() -> Self {
        Self {
            sum: 0,
            squares_sum: 0,
            count: 0,
        }
    }
}
