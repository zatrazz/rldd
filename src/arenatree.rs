// Tree-like data structure, used while resolving the input binary.

pub struct Node<T>
where
    T: PartialEq,
{
    pub idx: usize,
    pub val: T,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
}

impl<T> Node<T>
where
    T: PartialEq,
{
    fn new(idx: usize, val: T) -> Self {
        Self {
            idx,
            val,
            parent: None,
            children: vec![],
        }
    }
}

pub struct ArenaTree<T>
where
    T: PartialEq,
{
    pub arena: Vec<Node<T>>,
}

impl<T> ArenaTree<T>
where
    T: PartialEq,
{
    pub fn new() -> Self {
        Self {
            arena: Vec::<Node<T>>::new(),
        }
    }

    pub fn addroot(&mut self, val: T) -> usize {
        let idx = self.arena.len();
        self.arena.push(Node::new(idx, val));
        idx
    }

    pub fn addnode(&mut self, val: T, parent: usize) -> usize {
        let idx = self.arena.len();
        self.arena.push(Node::new(idx, val));
        self.arena[parent].children.push(idx);
        self.arena[idx].parent = Some(parent);
        idx
    }
}
