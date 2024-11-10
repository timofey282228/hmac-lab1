use super::attack::Attack;
use super::attack_options::AttackOptions;
use super::attack_stats::AttackStats;
use crate::{display_generated_message, MessaageGenerator};
use std::collections::HashMap;

pub struct CollisionSearch<'a, G: MessaageGenerator, F, H: Eq + std::hash::Hash>
where
    F: Fn(&[u8]) -> H,
{
    initial_message: &'a str,
    message_generator: G,
    hash_function: F,
    options: AttackOptions,
}

impl<'a, G: MessaageGenerator, F, H: Eq + std::hash::Hash> CollisionSearch<'a, G, F, H>
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

impl<'a, G: MessaageGenerator, F, H: Eq + std::hash::Hash> Attack for CollisionSearch<'a, G, F, H>
where
    F: Fn(&[u8]) -> H,
{
    fn run(&mut self) -> AttackStats {
        let message = self.initial_message;
        let mut map: HashMap<H, (u64, String)> = HashMap::new();
        let mut attack_stats = AttackStats::default();
        let initial_hash = (self.hash_function)(message.as_bytes());
        let mut last_message = message.to_owned();

        let final_message_info: (u64, String);
        let colliding_message_info: (u64, String);

        map.insert(initial_hash, (0, message.to_owned()));

        loop {
            let new_message: String;
            if self.options.incremental_transform {
                new_message = self.message_generator.generate_from(&last_message);
            } else {
                new_message = self.message_generator.generate_from(message);
            }

            attack_stats.generated_messages_count += 1;

            // TODO: 👇
            if attack_stats.generated_messages_count <= 30 {
                display_generated_message(&new_message);
            }

            let new_message_hash = (self.hash_function)(new_message.as_bytes());

            if map.contains_key(&new_message_hash) {
                let collision = map
                    .get_key_value(&new_message_hash)
                    .expect("success since map.contains_key(&hash) was true");

                if self.options.incremental_transform {
                    last_message = new_message.to_owned();
                }

                if &collision.1 .1 == &new_message {
                    // same message, not a collision
                    continue;
                }

                final_message_info = (attack_stats.generated_messages_count, new_message);
                colliding_message_info = collision.1.to_owned();
                break;
            }

            if self.options.incremental_transform {
                last_message = new_message.to_owned();
            }

            map.insert(
                new_message_hash,
                (attack_stats.generated_messages_count, new_message),
            );
        }

        // TODO: 👇
        println!("...");
        display_generated_message(&final_message_info.1);
        println!(
            "Collision:\n          hash({}) == hash({})\n          (#{} and #{})",
            colliding_message_info.1,
            final_message_info.1,
            colliding_message_info.0,
            final_message_info.0
        );

        attack_stats
    }
}
