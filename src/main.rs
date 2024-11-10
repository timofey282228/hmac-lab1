use std::error::Error;
use crate::attacks::attack::Attack;
use crate::attacks::collision_search::CollisionSearch;
use crate::attacks::preimage_search::RandomPreimageSearch;
use crate::message_gen::{
    MessaageGenerator, NaturalNumberMessageGenerator, RandomChangeMessageGenerator,
};
use attacks::attack_options::AttackOptions;
use attacks::attack_stats::CumulativeAttackStats;
use rand::Rng;
use sha2::{Digest, Sha384};

pub mod attacks;
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

fn prepare_run_unique_message(prefix: &str) -> String {
    let mut per_run_init_message = String::from(prefix);
    per_run_init_message.push_str(INITIAL_MESSAGE);
    per_run_init_message.push(' ');

    let message_suffix: String = (0..PRE_ATTACK_RUN_COUNT / 5)
        .map(|_| rand::thread_rng().gen_range('!'..='~'))
        .filter(|c| c.is_ascii_graphic())
        .collect();

    per_run_init_message.push_str(&message_suffix);
    per_run_init_message
}

fn display_init_msg_info(message: &str) {
    let sha384 = Sha384::digest(message.as_bytes());
    println!("Initial message: {message}\n {:X}", sha384);
}

fn display_generated_message(message: &str) {
    let sha384 = Sha384::digest(message.as_bytes());
    println!("| {} | {:X} | ", message, sha384);
}

fn main() -> Result<(), Box<dyn Error>>{
    let mut wrt = csv::Writer::from_path("pre_1.csv")?;
    let mut cas_pre_1 = CumulativeAttackStats::default();
    for i in 1..=PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        display_init_msg_info(&per_run_init_message);

        let mut attack = RandomPreimageSearch::new(
            &per_run_init_message,
            NaturalNumberMessageGenerator::default(),
            my_hash_16,
            AttackOptions::default(),
        );

        let attack_stats = attack.run();
        cas_pre_1.include_attack(&attack_stats);

        wrt.write_record([
            format!("{}", i),
            format!("{}", attack_stats.generated_messages_count),
        ])?;
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_pre_1.average(),
        var = cas_pre_1.variance(),
        int = cas_pre_1.confidence_interval()
    );

    let mut wrt = csv::Writer::from_path("pre_2.csv")?;
    let mut cas_pre_2 = CumulativeAttackStats::default();
    for i in 1..=PRE_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("PRE ");
        display_init_msg_info(&per_run_init_message);

        let mut attack = RandomPreimageSearch::new(
            &per_run_init_message,
            RandomChangeMessageGenerator::default(),
            my_hash_16,
            AttackOptions::default().set_incremental_transform(true),
        );

        let attack_stats = attack.run();
        cas_pre_2.include_attack(&attack_stats);

        wrt.write_record([
            format!("{}", i),
            format!("{}", attack_stats.generated_messages_count),
        ])?;
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_pre_2.average(),
        var = cas_pre_2.variance(),
        int = cas_pre_2.confidence_interval()
    );

    let mut wrt = csv::Writer::from_path("bd_1.csv")?;
    let mut cas_bd_1 = CumulativeAttackStats::default();
    for i in 1..=BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        display_init_msg_info(&per_run_init_message);

        let mut attack = CollisionSearch::new(
            &per_run_init_message,
            NaturalNumberMessageGenerator::default(),
            my_hash_32,
            AttackOptions::default(),
        );

        let attack_stats = attack.run();
        cas_bd_1.include_attack(&attack_stats);

        wrt.write_record([
            format!("{}", i),
            format!("{}", attack_stats.generated_messages_count),
        ])?;
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_bd_1.average(),
        var = cas_bd_1.variance(),
        int = cas_bd_1.confidence_interval()
    );

    let mut wrt = csv::Writer::from_path("bd_2.csv")?;
    let mut cas_bd_2 = CumulativeAttackStats::default();
    for i in 1..=BD_ATTACK_RUN_COUNT {
        let per_run_init_message = prepare_run_unique_message("BD ");
        display_init_msg_info(&per_run_init_message);

        let mut attack = CollisionSearch::new(
            &per_run_init_message,
            RandomChangeMessageGenerator::default(),
            my_hash_32,
            AttackOptions::default().set_incremental_transform(true),
        );

        let attack_stats = attack.run();
        cas_bd_2.include_attack(&attack_stats);

        wrt.write_record([
            format!("{}", i),
            format!("{}", attack_stats.generated_messages_count),
        ])?;
    }

    println!(
        "Average: {avg}; variance: {var}; interval: {int:?}",
        avg = cas_bd_2.average(),
        var = cas_bd_2.variance(),
        int = cas_bd_2.confidence_interval()
    );

    Ok(())
}
