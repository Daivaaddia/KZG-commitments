from collections import deque
import time
import hashlib

class Node:
    def __init__(self, data):
        self.data = data
        self.left = None
        self.right = None
        self.parent = None
        self.sibling = None
        self.plainData = None # Only for leaves
        self.proof = []

class MerkleTree:
    def __init__(self):
        self.root = None
        self.tree = []
        self.leaves = []
        self.dataToNode = {}
    
    def _hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _createTree(self, leaves):
        current_level = []
        for leaf in leaves:
            leafNode = Node(self._hash(leaf))
            leafNode.plainData = leaf
            self.dataToNode[leaf] = leafNode
            current_level.append(leafNode)

        self.leaves = current_level[:]
        self.tree = [current_level]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last elem if odd number of elements
                    right = left

                # Enforce an ordering
                if left.data > right.data:
                    concat = left.data + right.data
                else: 
                    concat = right.data + left.data

                parentNode = Node(self._hash(concat))

                parentNode.left = left
                parentNode.right = right
                left.parent = parentNode
                right.parent = parentNode
                left.sibling = right
                right.sibling = left

                next_level.append(parentNode)

            current_level = next_level
            self.tree.insert(0, current_level)

        self.root = current_level[0]

    def _generateProofs(self):
        totalTime = 0
        for leaf in self.leaves:
            start = time.time()

            curr = leaf
            while curr.parent != None:
                leaf.proof.append(curr.sibling.data)
                curr = curr.parent

            totalTime += time.time() - start
        
        return totalTime / len(self.leaves)


    def _setupDict():
        for i in range(len(self.leaves)):
            self.dataToNode[self.leaves[i]] = i

    def create(self, leaves):
        self._createTree(leaves)

    def setupProofs(self):
        return self._generateProofs()

    def getProof(self, data):
        node = self.dataToNode[data]

        if node == None:
            return None
        return node.proof

    def verify(self, data, proof):
        hashed = self._hash(data)
        for p in proof:
            if hashed > p:
                concat = hashed + p
            else: 
                concat = p + hashed
            hashed = self._hash(concat)
        
        return hashed == self.root.data

    def _printHelper(self, node, level, res):
        if node is None:
            return

        if len(res) <= level:
            res.append([])

        res[level].append(node)

        self._printHelper(node.left, level + 1, res)
        self._printHelper(node.right, level + 1, res)

    def printLevelOrder(self):
        res = []
        self._printHelper(self.root, 0, res)
        for level in res:
            print("-----------------")
            for a in level:
                if a.parent is None:
                    print("Data: ", a.data)
                else:
                    print("Data: ", a.data, " Parent: ", a.parent.data)
        

    def getRoot(self):
        return self.root.data


        
            