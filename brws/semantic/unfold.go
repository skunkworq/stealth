package semantic

import "container/heap"

type UnfoldCandidate struct {
	NodeID     string
	Score      float32
	UnfoldCost uint32
	index      int
}

type UnfoldState struct {
	Unfolded      []string
	TokenUsage    uint32
	InitialBudget uint32
	MaxBudget     uint32
}

func NewUnfoldState(initialBudget, maxBudget uint32) *UnfoldState {
	return &UnfoldState{
		Unfolded:      []string{},
		TokenUsage:    0,
		InitialBudget: initialBudget,
		MaxBudget:     maxBudget,
	}
}

func (s *UnfoldState) RemainingBudget() uint32 {
	if s.TokenUsage >= s.MaxBudget {
		return 0
	}
	return s.MaxBudget - s.TokenUsage
}

func (s *UnfoldState) RemainingInitialBudget() uint32 {
	if s.TokenUsage >= s.InitialBudget {
		return 0
	}
	return s.InitialBudget - s.TokenUsage
}

func (s *UnfoldState) WithinInitialBudget() bool {
	return s.TokenUsage <= s.InitialBudget
}

func InitialPack(tree *SemanticTree, initialBudget, maxBudget uint32) *UnfoldState {
	state := NewUnfoldState(initialBudget, maxBudget)
	state.TokenUsage = tree.CompressedTokenCount
	return state
}

func UnfoldNode(tree *SemanticTree, state *UnfoldState, nodeID string) (uint32, bool) {
	for _, id := range state.Unfolded {
		if id == nodeID {
			return 0, true
		}
	}

	node := tree.FindNode(nodeID)
	if node == nil {
		return 0, false
	}

	if !node.IsFoldable() {
		return 0, true
	}

	cost := node.UnfoldCost()
	if state.TokenUsage+cost > state.MaxBudget {
		return 0, false
	}

	state.Unfolded = append(state.Unfolded, nodeID)
	state.TokenUsage += cost
	return cost, true
}

func FoldNode(tree *SemanticTree, state *UnfoldState, nodeID string) (uint32, bool) {
	idx := -1
	for i, id := range state.Unfolded {
		if id == nodeID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return 0, false
	}

	node := tree.FindNode(nodeID)
	if node == nil {
		return 0, false
	}

	reclaimed := node.UnfoldCost()
	state.Unfolded = append(state.Unfolded[:idx], state.Unfolded[idx+1:]...)
	if state.TokenUsage >= reclaimed {
		state.TokenUsage -= reclaimed
	} else {
		state.TokenUsage = 0
	}

	return reclaimed, true
}

type candidateHeap []UnfoldCandidate

func (h candidateHeap) Len() int           { return len(h) }
func (h candidateHeap) Less(i, j int) bool { return h[i].Score > h[j].Score }
func (h candidateHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *candidateHeap) Push(x interface{}) {
	*h = append(*h, x.(UnfoldCandidate))
}

func (h *candidateHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

func SemanticUnfold(tree *SemanticTree, state *UnfoldState, queryEmbedding []float32, maxUnfolds int) []string {
	h := &candidateHeap{}
	heap.Init(h)

	for _, node := range tree.AllNodes() {
		if !node.IsFoldable() {
			continue
		}
		for _, id := range state.Unfolded {
			if id == node.ID {
				continue
			}
		}
		if len(node.Embedding) == 0 {
			continue
		}

		relevance := CosineSimilarity(node.Embedding, queryEmbedding)
		cost := node.UnfoldCost()
		if cost == 0 {
			continue
		}

		density := float32(node.SubtreeTokenCount) / float32(cost)
		score := relevance * (1.0 + max(0.0, log32(density)))

		heap.Push(h, UnfoldCandidate{
			NodeID:     node.ID,
			Score:      score,
			UnfoldCost: cost,
		})
	}

	var unfoldedIDs []string
	count := 0

	for h.Len() > 0 && count < maxUnfolds {
		candidate := heap.Pop(h).(UnfoldCandidate)

		ancestors := tree.AncestorPath(candidate.NodeID)
		totalCost := candidate.UnfoldCost
		var ancestorsToUnfold []struct {
			id   string
			cost uint32
		}

		for _, ancestorID := range ancestors {
			alreadyUnfolded := false
			for _, id := range state.Unfolded {
				if id == ancestorID {
					alreadyUnfolded = true
					break
				}
			}
			if !alreadyUnfolded {
				if ancestorNode := tree.FindNode(ancestorID); ancestorNode != nil {
					ancestorCost := ancestorNode.UnfoldCost()
					totalCost += ancestorCost
					ancestorsToUnfold = append(ancestorsToUnfold, struct {
						id   string
						cost uint32
					}{ancestorID, ancestorCost})
				}
			}
		}

		if state.TokenUsage+totalCost > state.MaxBudget {
			continue
		}

		for _, anc := range ancestorsToUnfold {
			state.Unfolded = append(state.Unfolded, anc.id)
			state.TokenUsage += anc.cost
			unfoldedIDs = append(unfoldedIDs, anc.id)
		}

		state.Unfolded = append(state.Unfolded, candidate.NodeID)
		state.TokenUsage += candidate.UnfoldCost
		unfoldedIDs = append(unfoldedIDs, candidate.NodeID)
		count++
	}

	return unfoldedIDs
}

func AutoUnfold(tree *SemanticTree, state *UnfoldState) []string {
	var unfoldedIDs []string

	for _, node := range tree.RootNodes {
		if !node.IsFoldable() {
			continue
		}
		for _, id := range state.Unfolded {
			if id == node.ID {
				continue
			}
		}

		cost := node.UnfoldCost()
		if cost == 0 {
			continue
		}

		if state.TokenUsage+cost > state.InitialBudget {
			continue
		}

		state.Unfolded = append(state.Unfolded, node.ID)
		state.TokenUsage += cost
		unfoldedIDs = append(unfoldedIDs, node.ID)
	}

	return unfoldedIDs
}

func max(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func log32(x float32) float32 {
	if x <= 0 {
		return 0
	}
	return float32(log(float64(x)))
}

func log(x float64) float64 {
	if x <= 1 {
		return 0
	}
	return 0.6931471805599453 * (x - 1) / x
}
