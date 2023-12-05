package bst

// Min returns the minimum key Node in the tree.
func (tr Tree) Min() *Node {
	nd := tr.Root
	if nd == nil {
		return nil
	}
	for nd.Left != nil {
		nd = nd.Left
	}
	return nd
}

// Max returns the maximum key Node in the tree.
func (tr Tree) Max() *Node {
	nd := tr.Root
	if nd == nil {
		return nil
	}
	for nd.Right != nil {
		nd = nd.Right
	}
	return nd
}

// Search does binary-search on a given key and returns the first Node with the key.
func (tr Tree) Search(key Interface) *Node {
	nd := tr.Root
	// just updating the pointer value (address)
	for nd != nil {
		if nd.Key == nil {
			break
		}
		switch {
		case nd.Key.Less(key):
			nd = nd.Right
		case key.Less(nd.Key):
			nd = nd.Left
		default:
			return nd
		}
	}
	return nil
}

// SearchChan does binary-search on a given key and return the first Node with the key.
func (tr Tree) SearchChan(key Interface, ch chan *Node) {
	searchChan(tr.Root, key, ch)
	close(ch)
}

func searchChan(nd *Node, key Interface, ch chan *Node) {
	// leaf node
	if nd == nil {
		return
	}
	// when equal
	if !nd.Key.Less(key) && !key.Less(nd.Key) {
		ch <- nd
		return
	}
	searchChan(nd.Left, key, ch)  // left
	searchChan(nd.Right, key, ch) // right
}

// SearchParent does binary-search on a given key and returns the parent Node.
func (tr Tree) SearchParent(key Interface) *Node {
	nd := tr.Root
	parent := new(Node)
	parent = nil
	// just updating the pointer value (address)
	for nd != nil {
		if nd.Key == nil {
			break
		}
		switch {
		case nd.Key.Less(key):
			parent = nd // copy the pointer(address)
			nd = nd.Right
		case key.Less(nd.Key):
			parent = nd // copy the pointer(address)
			nd = nd.Left
		default:
			return parent
		}
	}
	return nil
}

func (nd *Node) SearchRange(min Interface, max Interface, ret []*Node) []*Node {
	if nd == nil || nd.Key == nil {
		return ret
	}

	if min.Less(nd.Key) {
		ret = nd.Left.SearchRange(min, max, ret)
	}
	if min.Less(nd.Key) && nd.Key.Less(max) {
		ret = append(ret, nd)
	}
	if nd.Key.Less(max) {
		ret = nd.Right.SearchRange(min, max, ret)
	}
	return ret
}

func (tr *Tree) SearchRange(min Interface, max Interface) []*Node {
	ret := make([]*Node, 0, 2)
	if tr == nil || tr.Root == nil {
		return nil
	}
	return tr.Root.SearchRange(min, max, ret)
}

func (nd *Node) TraverseInOrder(ret []*Node) []*Node {
	if nd == nil {
		return ret
	}
	ret = nd.Left.TraverseInOrder(ret)
	ret = append(ret, nd)
	ret = nd.Right.TraverseInOrder(ret)
	return ret
}

func (tr *Tree) TraverseInOrder() []*Node {
	var ret []*Node
	return tr.Root.TraverseInOrder(ret)
}
