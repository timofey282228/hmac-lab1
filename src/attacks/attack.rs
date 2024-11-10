use super::attack_stats::AttackStats;

pub trait Attack {
    fn run(&mut self) -> AttackStats;
}
