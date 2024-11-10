use super::attack::Attack;
use super::attack_options::AttackOptions;
use super::attack_stats::AttackStats;
use crate::MessaageGenerator;
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
        let mut map: HashMap<H, String> = HashMap::new();
        let mut attack_stats = AttackStats::default();
        let initial_hash = (self.hash_function)(message.as_bytes());
        let mut last_message = message.to_owned();

        map.insert(initial_hash, message.to_owned());

        loop {
            let new_message: String;
            if self.options.incremental_transform {
                new_message = self.message_generator.generate_from(&last_message);
            } else {
                new_message = self.message_generator.generate_from(message);
            }

            attack_stats.generated_messages_count += 1;
            let new_message_hash = (self.hash_function)(new_message.as_bytes());

            if map.contains_key(&new_message_hash) {
                let collision = map
                    .get_key_value(&new_message_hash)
                    .expect("map.contains_key(&hash) was true");

                if collision.1 == &new_message {
                    // same message, not a collision
                    if self.options.incremental_transform {
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

            if self.options.incremental_transform {
                last_message = new_message.to_owned();
            }

            map.insert(new_message_hash, new_message);
        }

        attack_stats
    }
}
