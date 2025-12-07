pub struct State {
    pub initialized: bool,
    pub total_blocks: u64,
    pub subject_name_to_height: std::collections::HashMap<String, String>,
}

impl State {
    pub fn new() -> Self {
        State {
            initialized: false,
            total_blocks: 0,
            subject_name_to_height: std::collections::HashMap::new(),
        }
    }

    pub fn mark_initialized(&mut self) {
        self.initialized = true;
    }

    pub fn increment_block_count(&mut self) {
        self.total_blocks += 1;
    }

    pub fn map_subject_name_to_uid(&mut self, subject_name: String, uid: String) {
        self.subject_name_to_height.insert(subject_name, uid);
    }
}
