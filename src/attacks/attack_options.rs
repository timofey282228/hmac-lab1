pub struct AttackOptions {
    pub(in crate::attacks) incremental_transform: bool,
}

impl Default for AttackOptions {
    fn default() -> Self {
        Self {
            incremental_transform: false,
        }
    }
}

impl AttackOptions {
    pub fn set_incremental_transform(mut self, incremental_transform: bool) -> Self {
        self.incremental_transform = incremental_transform;
        self
    }
}
