package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type ZSLMerkleTree struct {
	TreeDepth        uint
	MaxNumElements   uint
	EmptyRoots       []string
	NumCommitments   uint
	MapCommitIndices map[string]uint
	MapCommitments   map[uint]string
}

type PublicMarkleTreeAPI struct {
	tree *ZSLMerkleTree
}

func InitMerkleApi() *PublicMarkleTreeAPI {
	return &PublicMarkleTreeAPI{}
}

func (api *PublicMarkleTreeAPI) Init(depth uint) {
	api.tree = NewZSLMerkleTree(depth)
}

func NewZSLMerkleTree(depth uint) *ZSLMerkleTree {
	tree := &ZSLMerkleTree{
		TreeDepth:        depth,
		MaxNumElements:   1 << depth,
		EmptyRoots:       make([]string, 0),
		MapCommitIndices: make(map[string]uint),
		MapCommitments:   make(map[uint]string),
	}

	tree.createEmptyRoots(depth)
	fmt.Println(tree.EmptyRoots)
	return tree
}

func (tree *ZSLMerkleTree) createEmptyRoots(depth uint) {
	var root string = "0x00"
	tree.EmptyRoots = append(tree.EmptyRoots, root)
	for i := uint(0); i < depth-1; i++ {
		root = tree.combine(root, root)
		tree.EmptyRoots = append(tree.EmptyRoots, root)
	}
}

func (tree *ZSLMerkleTree) combine(left string, right string) string {
	hasher := sha256.New()
	hasher.Write([]byte(left + right))
	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash
}

func (tree *ZSLMerkleTree) insertCommitment(commitment string) bool {
	// check if commitment is already inserted
	if _, exists := tree.MapCommitIndices[commitment]; exists {
		return false
	}

	// check if the tree is full
	if tree.NumCommitments >= tree.MaxNumElements {
		return false
	}

	// Insert the commitment and increment the number of commitments
	tree.MapCommitIndices[commitment] = tree.NumCommitments
	tree.MapCommitments[tree.NumCommitments] = commitment
	tree.NumCommitments++

	return true
}

func (tree *ZSLMerkleTree) verifyMerklePath(merklePath []string, commitment string, path uint, root string) bool {
	// Check if the commitment is present in the tree
	if _, exists := tree.MapCommitIndices[commitment]; !exists {
		return false
	}

	// Calculate the Merkle root using the path
	computedRoot := commitment
	for i := uint(0); i < tree.TreeDepth; i++ {
		if path&(1<<i) != 0 {
			computedRoot = tree.combine(merklePath[i], computedRoot)
		} else {
			computedRoot = tree.combine(computedRoot, merklePath[i])
		}
	}

	// Compare the computed root with the given root
	return computedRoot == root
}

func (tree *ZSLMerkleTree) _calcSubtree(index uint, itemDepth uint) string {
	// Use pre-computed empty tree root if we know other half of tree is empty
	if tree.NumCommitments <= index<<itemDepth {
		return tree.EmptyRoots[itemDepth]
	}

	if itemDepth == 0 {
		mapIndex := index + 1
		return tree.MapCommitments[mapIndex]
	} else {
		left := tree._calcSubtree(index<<1, itemDepth-1)
		right := tree._calcSubtree((index<<1)+1, itemDepth-1)
		return tree.combine(left, right)
	}
}

func (tree *ZSLMerkleTree) getWitness(commitment string) (uint, []string) {
	mapIndex := tree.MapCommitIndices[commitment]
	if mapIndex == 0 {
		panic("mapIndex must be greater than 0")
	}

	index := mapIndex - 1
	uncles := make([]string, tree.TreeDepth)
	curDepth := uint(0)
	curIndex := index
	i := uint(0)

	for curDepth < tree.TreeDepth {
		uncles[i] = tree._calcSubtree(curIndex^1, curDepth)
		curDepth++
		curIndex = curIndex >> 1
		i++
	}

	return index, uncles
}

func (api *PublicMarkleTreeAPI) GetWitness(commitment string) (uint, []string) {
	return api.tree.getWitness(commitment)
}


func (api *PublicMarkleTreeAPI) InsertCommitment(commitment string) bool {
	return api.tree.insertCommitment(commitment)
}

func (api *PublicMarkleTreeAPI) VerifyMerklePath(merklePath []string, commitment string, path uint, root string) bool {
	return api.tree.verifyMerklePath(merklePath, commitment, path, root)
}

