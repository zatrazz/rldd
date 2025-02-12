// Tree-like data structure, used while resolving the input binary.

#[derive(Debug)]
pub struct Node<T>
where
    T: PartialEq,
{
    pub val: T,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

impl<T> Node<T>
where
    T: PartialEq,
{
    fn new(val: T) -> Self {
        Self {
            val,
            parent: None,
            children: vec![],
        }
    }
}

pub trait EqualString {
    fn eqstr(&self, other: &str) -> bool;
}

#[derive(Debug)]
pub struct ArenaTree<T>
where
    T: PartialEq,
{
    pub arena: Vec<Node<T>>,
}

impl<T> ArenaTree<T>
where
    T: PartialEq + EqualString + Clone,
{
    pub fn new() -> Self {
        Self {
            arena: Vec::<Node<T>>::new(),
        }
    }

    pub fn addroot(&mut self, val: T) -> usize {
        let idx = self.arena.len();
        self.arena.push(Node::new(val));
        idx
    }

    pub fn addnode(&mut self, val: T, parent: usize) -> usize {
        let idx = self.arena.len();
        self.arena.push(Node::new(val));
        self.arena[parent].children.push(idx);
        self.arena[idx].parent = Some(parent);
        idx
    }

    pub fn get(&mut self, val: &str) -> Option<T> {
        for node in &self.arena {
            if node.val.eqstr(val) {
                return Some(node.val.clone());
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn contains(&self, val: &str) -> bool {
        for node in &self.arena {
            if node.val.eqstr(val) {
                return true;
            }
        }
        false
    }
}
