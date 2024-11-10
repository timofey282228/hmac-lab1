use crate::QUANTILE_0995;

pub struct AttackStats {
    pub generated_messages_count: u64,
}

pub struct CumulativeAttackStats {
    sum: u64,
    squares_sum: u64,
    count: u64,
}

impl CumulativeAttackStats {
    pub fn include_attack(&mut self, attack: &AttackStats) {
        self.sum += attack.generated_messages_count;
        self.squares_sum += attack.generated_messages_count.pow(2);
        self.count += 1;
    }

    pub fn average(&self) -> f64 {
        self.sum as f64 / self.count as f64
    }

    pub fn variance(&self) -> f64 {
        (self.squares_sum as f64 / self.count as f64)
            - (self.sum as f64 / self.count as f64).powi(2)
    }

    pub fn confidence_interval(&self) -> (f64, f64) {
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
