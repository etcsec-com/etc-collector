/**
 * Graph Utilities for Attack Path Analysis
 *
 * Provides graph data structures and algorithms for analyzing
 * privilege escalation paths in Active Directory.
 *
 * Phase 2: Attack Paths Detection
 */

import { ADUser, ADGroup, ADComputer } from '../types/ad.types';
import { AclEntry } from '../types/ad.types';

/**
 * Node types in the attack graph
 */
export type NodeType = 'user' | 'group' | 'computer' | 'gpo' | 'ou' | 'domain';

/**
 * Edge types representing relationships
 */
export type EdgeType =
  | 'memberOf' // Group membership
  | 'hasMember' // Inverse of memberOf
  | 'canModify' // ACL-based write access
  | 'canRead' // ACL-based read access
  | 'delegateTo' // Constrained delegation target
  | 'rbcdFrom' // RBCD - can act on behalf of
  | 'adminTo' // Local admin rights
  | 'owns' // Object ownership
  | 'gpLink' // GPO linked to OU/Domain
  | 'contains'; // OU contains object

/**
 * Graph node representing an AD object
 */
export interface GraphNode {
  dn: string;
  type: NodeType;
  name: string;
  isPrivileged?: boolean;
  isEnabled?: boolean;
  attributes?: Record<string, unknown>;
}

/**
 * Graph edge representing a relationship
 */
export interface GraphEdge {
  source: string; // Source DN
  target: string; // Target DN
  type: EdgeType;
  accessMask?: number; // For ACL edges
  isInherited?: boolean;
}

/**
 * Attack path from source to target
 */
export interface AttackPath {
  source: GraphNode;
  target: GraphNode;
  edges: GraphEdge[];
  length: number;
  riskScore: number;
}

/**
 * Dangerous ACL rights that enable privilege escalation
 */
export const DANGEROUS_RIGHTS = {
  GENERIC_ALL: 0x10000000,
  GENERIC_WRITE: 0x40000000,
  WRITE_DACL: 0x00040000,
  WRITE_OWNER: 0x00080000,
  WRITE_PROPERTY: 0x00000020,
  SELF: 0x00000008,
  EXTENDED_RIGHT: 0x00000100,
};

/**
 * Well-known privileged group names
 */
export const PRIVILEGED_GROUPS = [
  'Domain Admins',
  'Enterprise Admins',
  'Administrators',
  'Schema Admins',
  'Account Operators',
  'Backup Operators',
  'Server Operators',
  'Print Operators',
  'DnsAdmins',
  'Domain Controllers',
  'Group Policy Creator Owners',
];

/**
 * Attack Graph for analyzing privilege escalation paths
 */
export class AttackGraph {
  private nodes: Map<string, GraphNode> = new Map();
  private outEdges: Map<string, GraphEdge[]> = new Map();
  private inEdges: Map<string, GraphEdge[]> = new Map();
  private privilegedDNs: Set<string> = new Set();

  /**
   * Add a node to the graph
   */
  addNode(node: GraphNode): void {
    const normalizedDn = node.dn.toLowerCase();
    this.nodes.set(normalizedDn, { ...node, dn: normalizedDn });

    if (!this.outEdges.has(normalizedDn)) {
      this.outEdges.set(normalizedDn, []);
    }
    if (!this.inEdges.has(normalizedDn)) {
      this.inEdges.set(normalizedDn, []);
    }

    if (node.isPrivileged) {
      this.privilegedDNs.add(normalizedDn);
    }
  }

  /**
   * Add an edge to the graph
   */
  addEdge(edge: GraphEdge): void {
    const normalizedEdge: GraphEdge = {
      ...edge,
      source: edge.source.toLowerCase(),
      target: edge.target.toLowerCase(),
    };

    // Add to outgoing edges
    const outList = this.outEdges.get(normalizedEdge.source);
    if (outList) {
      outList.push(normalizedEdge);
    } else {
      this.outEdges.set(normalizedEdge.source, [normalizedEdge]);
    }

    // Add to incoming edges
    const inList = this.inEdges.get(normalizedEdge.target);
    if (inList) {
      inList.push(normalizedEdge);
    } else {
      this.inEdges.set(normalizedEdge.target, [normalizedEdge]);
    }
  }

  /**
   * Get a node by DN
   */
  getNode(dn: string): GraphNode | undefined {
    return this.nodes.get(dn.toLowerCase());
  }

  /**
   * Get all outgoing edges from a node
   */
  getOutEdges(dn: string): GraphEdge[] {
    return this.outEdges.get(dn.toLowerCase()) || [];
  }

  /**
   * Get all incoming edges to a node
   */
  getInEdges(dn: string): GraphEdge[] {
    return this.inEdges.get(dn.toLowerCase()) || [];
  }

  /**
   * Get all privileged nodes
   */
  getPrivilegedNodes(): GraphNode[] {
    return Array.from(this.privilegedDNs)
      .map((dn) => this.nodes.get(dn))
      .filter((n): n is GraphNode => n !== undefined);
  }

  /**
   * Mark a node as privileged
   */
  markAsPrivileged(dn: string): void {
    const normalizedDn = dn.toLowerCase();
    this.privilegedDNs.add(normalizedDn);
    const node = this.nodes.get(normalizedDn);
    if (node) {
      node.isPrivileged = true;
    }
  }

  /**
   * Check if a node is privileged
   */
  isPrivileged(dn: string): boolean {
    return this.privilegedDNs.has(dn.toLowerCase());
  }

  /**
   * Find shortest path from source to any privileged node using BFS
   */
  findShortestPathToPrivileged(sourceDn: string, maxDepth = 5): AttackPath | null {
    const source = this.getNode(sourceDn);
    if (!source) return null;

    // BFS queue: [currentDN, path of edges]
    const queue: [string, GraphEdge[]][] = [[sourceDn.toLowerCase(), []]];
    const visited = new Set<string>([sourceDn.toLowerCase()]);

    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;

      const [currentDn, path] = item;

      // Check depth limit
      if (path.length >= maxDepth) continue;

      // Explore neighbors
      const edges = this.getOutEdges(currentDn);
      for (const edge of edges) {
        if (visited.has(edge.target)) continue;
        visited.add(edge.target);

        const newPath = [...path, edge];
        const targetNode = this.getNode(edge.target);

        // Found a privileged target
        if (targetNode && this.isPrivileged(edge.target)) {
          return {
            source,
            target: targetNode,
            edges: newPath,
            length: newPath.length,
            riskScore: this.calculatePathRisk(newPath),
          };
        }

        queue.push([edge.target, newPath]);
      }
    }

    return null;
  }

  /**
   * Find all paths to privileged nodes up to maxDepth
   */
  findAllPathsToPrivileged(sourceDn: string, maxDepth = 5, maxPaths = 10): AttackPath[] {
    const source = this.getNode(sourceDn);
    if (!source) return [];

    const paths: AttackPath[] = [];
    const visited = new Set<string>();

    const dfs = (currentDn: string, currentPath: GraphEdge[]): void => {
      if (currentPath.length >= maxDepth || paths.length >= maxPaths) return;

      visited.add(currentDn);

      const edges = this.getOutEdges(currentDn);
      for (const edge of edges) {
        if (visited.has(edge.target)) continue;

        const newPath = [...currentPath, edge];
        const targetNode = this.getNode(edge.target);

        if (targetNode && this.isPrivileged(edge.target)) {
          paths.push({
            source,
            target: targetNode,
            edges: newPath,
            length: newPath.length,
            riskScore: this.calculatePathRisk(newPath),
          });
        }

        if (paths.length < maxPaths) {
          dfs(edge.target, newPath);
        }
      }

      visited.delete(currentDn);
    };

    dfs(sourceDn.toLowerCase(), []);
    return paths.sort((a, b) => a.length - b.length);
  }

  /**
   * Get all nodes reachable from source within maxDepth
   */
  getReachable(sourceDn: string, maxDepth = 5): Set<string> {
    const reachable = new Set<string>();
    const queue: [string, number][] = [[sourceDn.toLowerCase(), 0]];
    const visited = new Set<string>([sourceDn.toLowerCase()]);

    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;

      const [currentDn, depth] = item;
      reachable.add(currentDn);

      if (depth >= maxDepth) continue;

      const edges = this.getOutEdges(currentDn);
      for (const edge of edges) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push([edge.target, depth + 1]);
        }
      }
    }

    return reachable;
  }

  /**
   * Get recursive group members (including nested)
   */
  getRecursiveMembers(groupDn: string, maxDepth = 10): Set<string> {
    const members = new Set<string>();
    const visited = new Set<string>();

    const collectMembers = (dn: string, depth: number): void => {
      if (depth > maxDepth || visited.has(dn)) return;
      visited.add(dn);

      const edges = this.getInEdges(dn);
      for (const edge of edges) {
        if (edge.type === 'memberOf') {
          members.add(edge.source);
          // Recursively get members of nested groups
          const sourceNode = this.getNode(edge.source);
          if (sourceNode?.type === 'group') {
            collectMembers(edge.source, depth + 1);
          }
        }
      }
    };

    collectMembers(groupDn.toLowerCase(), 0);
    return members;
  }

  /**
   * Calculate risk score for an attack path
   */
  private calculatePathRisk(edges: GraphEdge[]): number {
    let score = 100 - edges.length * 10; // Shorter paths are riskier

    for (const edge of edges) {
      // ACL-based edges are high risk
      if (edge.type === 'canModify' || edge.type === 'owns') {
        score += 20;
      }
      // Delegation is medium risk
      if (edge.type === 'delegateTo' || edge.type === 'rbcdFrom') {
        score += 15;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Get graph statistics
   */
  getStats(): { nodes: number; edges: number; privileged: number } {
    let edgeCount = 0;
    this.outEdges.forEach((edges) => (edgeCount += edges.length));

    return {
      nodes: this.nodes.size,
      edges: edgeCount,
      privileged: this.privilegedDNs.size,
    };
  }
}

/**
 * Build a group membership graph from AD data
 */
export function buildGroupMembershipGraph(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[]
): AttackGraph {
  const graph = new AttackGraph();

  // Add groups as nodes
  for (const group of groups) {
    const isPrivileged = PRIVILEGED_GROUPS.some((pg) =>
      group.sAMAccountName?.toLowerCase().includes(pg.toLowerCase()) ||
      group.dn.toLowerCase().includes(`cn=${pg.toLowerCase()}`)
    );

    graph.addNode({
      dn: group.dn,
      type: 'group',
      name: group.sAMAccountName || group.displayName || group.dn,
      isPrivileged,
      isEnabled: true,
    });
  }

  // Add users as nodes
  for (const user of users) {
    graph.addNode({
      dn: user.dn,
      type: 'user',
      name: user.sAMAccountName || user.displayName || user.dn,
      isPrivileged: user.adminCount === 1,
      isEnabled: user.enabled,
      attributes: {
        hasSPN: (() => {
          const spn = user['servicePrincipalName'];
          return spn && Array.isArray(spn) && spn.length > 0;
        })(),
        hasNoPreauth: user.userAccountControl ? (user.userAccountControl & 0x400000) !== 0 : false,
      },
    });

    // Add membership edges
    if (user.memberOf) {
      for (const groupDn of user.memberOf) {
        graph.addEdge({
          source: user.dn,
          target: groupDn,
          type: 'memberOf',
        });
      }
    }
  }

  // Add computers as nodes
  for (const computer of computers) {
    graph.addNode({
      dn: computer.dn,
      type: 'computer',
      name: computer.sAMAccountName || computer.dNSHostName || computer.dn,
      isPrivileged: false,
      isEnabled: computer.enabled,
    });

    // Add membership edges
    const computerMemberOf = computer['memberOf'];
    if (computerMemberOf && Array.isArray(computerMemberOf)) {
      for (const groupDn of computerMemberOf) {
        graph.addEdge({
          source: computer.dn,
          target: groupDn,
          type: 'memberOf',
        });
      }
    }
  }

  // Add group nesting (group memberOf group)
  for (const group of groups) {
    if (group.memberOf) {
      for (const parentDn of group.memberOf) {
        graph.addEdge({
          source: group.dn,
          target: parentDn,
          type: 'memberOf',
        });
      }
    }
  }

  return graph;
}

/**
 * Build ACL-based attack graph
 */
export function buildAclGraph(
  aclEntries: AclEntry[],
  baseGraph: AttackGraph
): AttackGraph {
  for (const acl of aclEntries) {
    // Skip inherited ACEs (less interesting for attack paths)
    // Skip ALLOW-only (we're looking at dangerous permissions)

    const hasDangerousRight =
      (acl.accessMask & DANGEROUS_RIGHTS.GENERIC_ALL) !== 0 ||
      (acl.accessMask & DANGEROUS_RIGHTS.GENERIC_WRITE) !== 0 ||
      (acl.accessMask & DANGEROUS_RIGHTS.WRITE_DACL) !== 0 ||
      (acl.accessMask & DANGEROUS_RIGHTS.WRITE_OWNER) !== 0;

    // aceType is string '0' for ACCESS_ALLOWED_ACE_TYPE
    if (hasDangerousRight && String(acl.aceType) === '0') {
      baseGraph.addEdge({
        source: acl.trustee,
        target: acl.objectDn,
        type: 'canModify',
        accessMask: acl.accessMask,
        isInherited: false,
      });
    }
  }

  return baseGraph;
}

/**
 * Add delegation relationships to graph
 */
export function addDelegationEdges(
  users: ADUser[],
  computers: ADComputer[],
  graph: AttackGraph
): void {
  // Constrained delegation (users)
  for (const user of users) {
    const allowedToDelegateTo = (user as any)['msDS-AllowedToDelegateTo'];
    if (allowedToDelegateTo && Array.isArray(allowedToDelegateTo)) {
      for (const target of allowedToDelegateTo) {
        graph.addEdge({
          source: user.dn,
          target: target, // This is an SPN, need to resolve
          type: 'delegateTo',
        });
      }
    }
  }

  // Constrained delegation (computers)
  for (const computer of computers) {
    const allowedToDelegateTo = (computer as any)['msDS-AllowedToDelegateTo'];
    if (allowedToDelegateTo && Array.isArray(allowedToDelegateTo)) {
      for (const target of allowedToDelegateTo) {
        graph.addEdge({
          source: computer.dn,
          target: target,
          type: 'delegateTo',
        });
      }
    }

    // RBCD
    const rbcdAttr = (computer as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    if (rbcdAttr) {
      // RBCD allows the computer to accept delegation FROM the principals in this attribute
      // The edge direction is: principal -> computer (can act on behalf)
      graph.addEdge({
        source: computer.dn,
        target: computer.dn, // Self-reference to indicate RBCD is configured
        type: 'rbcdFrom',
      });
    }
  }
}

/**
 * Detect group nesting depth
 */
export function detectNestingDepth(
  groupDn: string,
  groups: ADGroup[],
  maxDepth = 10
): number {
  const groupMap = new Map<string, ADGroup>();
  for (const g of groups) {
    groupMap.set(g.dn.toLowerCase(), g);
  }

  const visited = new Set<string>();
  let maxFound = 0;

  const traverse = (dn: string, depth: number): void => {
    if (depth > maxDepth || visited.has(dn.toLowerCase())) return;
    visited.add(dn.toLowerCase());
    maxFound = Math.max(maxFound, depth);

    const group = groupMap.get(dn.toLowerCase());
    if (group?.memberOf) {
      for (const parentDn of group.memberOf) {
        traverse(parentDn, depth + 1);
      }
    }
  };

  traverse(groupDn, 0);
  return maxFound;
}

/**
 * Check if a DN is a member of privileged groups (recursive)
 */
export function isPrivilegedMember(
  dn: string,
  graph: AttackGraph,
  maxDepth = 10
): boolean {
  const reachable = graph.getReachable(dn, maxDepth);

  for (const targetDn of reachable) {
    if (graph.isPrivileged(targetDn)) {
      return true;
    }
  }

  return false;
}
