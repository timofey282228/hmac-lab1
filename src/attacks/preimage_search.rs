use crate::attacks::attack::*;
use crate::attacks::attack_options::AttackOptions;
use crate::message_gen::MessaageGenerator;
use super::attack_stats::AttackStats;

pub struct RandomPreimageSearch<'a, G: MessaageGenerator, F, H: Eq>
where
    F: Fn(&[u8]) -> H,
{
    initial_message: &'a str,
    message_generator: G,
    hash_function: F,
    options: AttackOptions,
}

impl<'a, G: MessaageGenerator, F, H: Eq> RandomPreimageSearch<'a, G, F, H>
where
    F: Fn(&[u8]) -> H,
{
    pub fn new(
        initial_message: &'a str,
        message_generator: G,
        hash_function: F,
        options: AttackOptions,
    ) -> Self {
        Self {
            initial_message,
            message_generator,
            hash_function,
            options,
        }
    }
}

impl<'a, G: MessaageGenerator, F, H: Eq> Attack for RandomPreimageSearch<'a, G, F, H>
where
    F: Fn(&[u8]) -> H,
{
    fn run(&mut self) -> AttackStats {
        let message = self.initial_message;
        let target_hash = (self.hash_function)(message.as_bytes());
        let mut other_message: String;
        let mut attack_stats = AttackStats::default();

        let mut last_message = message.to_owned();
        loop {
            if self.options.incremental_transform {
                other_message = self.message_generator.generate_from(&last_message);
            } else {
                other_message = self.message_generator.generate_from(message);
            }

            attack_stats.generated_messages_count += 1;

            let other_hash = (self.hash_function)(other_message.as_bytes());

            if target_hash == other_hash && message != other_message {
                break;
            }

            if self.options.incremental_transform {
                last_message = other_message;
            }
        }

        println!("Collision: {other_message} :-: {message}");
        attack_stats
    }
}

// std::hash::Hash + Eq
