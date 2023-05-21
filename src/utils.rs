#[derive(Clone, Debug)]
pub struct ConsecutiveList<T> {
    current_index: usize,
    list: Vec<T>,
}

impl<T: Clone> ConsecutiveList<T> {
    pub fn new(initial_value: T) -> Self {
        Self {
            current_index: 0,
            list: vec![initial_value],
        }
    }

    pub fn current(&self) -> T {
        self.list[self.current_index].clone()
    }

    pub fn set_next(&mut self, val: T) {
        self.list.push(val);
    }

    pub fn go_next(&mut self) -> bool {
        if self.list.len() == self.current_index + 1 {
            false
        } else {
            self.current_index += 1;
            true
        }
    }

    pub fn go_back(&mut self) -> bool {
        if self.list.len() == 1 {
            false
        } else {
            self.current_index -= 1;
            true
        }
    }

    #[allow(dead_code)]
    pub fn next(&self) -> Option<&T> {
        if self.list.len() < self.current_index + 1 {
            None
        } else {
            Some(&self.list[self.current_index])
        }
    }

    pub fn prev(&self) -> Option<&T> {
        if self.current_index == 0 {
            None
        } else {
            Some(&self.list[self.current_index - 1])
        }
    }
}
