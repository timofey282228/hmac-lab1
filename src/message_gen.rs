use rand::Rng;

pub trait MessaageGenerator {
    fn generate_from(&mut self, message: &str) -> String;
}

pub struct NaturalNumberMessageGenerator {
    counter: u64,
}

impl Default for NaturalNumberMessageGenerator {
    fn default() -> Self {
        Self { counter: 1 }
    }
}

impl MessaageGenerator for NaturalNumberMessageGenerator {
    fn generate_from(&mut self, message: &str) -> String {
        let mut new_message = String::from(message);
        new_message.push_str(&self.counter.to_string());
        self.counter += 1;

        new_message
    }
}

pub struct RandomChangeMessageGenerator {}

impl Default for RandomChangeMessageGenerator {
    fn default() -> Self {
        Self {}
    }
}

impl MessaageGenerator for RandomChangeMessageGenerator {
    fn generate_from(&mut self, message: &str) -> String {
        // choose a random character index
        let index = rand::thread_rng().gen_range(0..message.chars().count());

        // choose a random replacement character
        let new_char = rand::thread_rng().gen_range('!'..='~');

        let mut new_message = String::from(message);
        let replace_char_index = new_message
            .char_indices()
            .nth(index)
            .expect("index less than message.chars().count()");

        new_message.replace_range(
            replace_char_index.0..(replace_char_index.0 + replace_char_index.1.len_utf8()),
            &new_char.to_string(),
        );

        new_message
    }
}
