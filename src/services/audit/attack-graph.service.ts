/**
 * Attack Graph Service
 *
 * Builds and exports attack path data for visualization.
 * Uses BFS to find shortest paths from non-privileged objects
 * to privileged targets (Domain Admins, Enterprise Admins, etc.)
 */

import { ADUser, ADGroup, ADComputer, AclEntry } from '../../types/ad.types';
import { ADCSCertificateTemplate } from '../../types/adcs.types';
import { ADGPO } from '../../types/gpo.types';
import {
  AttackGraphExport,
  AttackGraphNode,
  AttackGraphRelation,
  AttackPath,
  AttackPathRisk,
  AttackPathType,
  AttackRelationType,
  AttackTarget,
  AttackGraphStats,
  AttackGraphUniqueNode,
  AttackChainElement,
  AttackEntryPoint,
  AttackNodeType,
  ACCESS_MASK,
  ACL_GUIDS,
  PRIVILEGED_SID_SUFFIXES,
  isAttackGraphNode,
} from '../../types/attack-graph.types';
import { logger } from '../../utils/logger';

/**
 * Internal graph node with additional metadata
 */
interface InternalNode {
  id: string; // SID or DN-based ID
  dn: string;
  name: string;
  type: AttackNodeType;
  sid?: string;
  isEnabled: boolean;
  isPrivileged: boolean;
  adminCount?: number;
  memberOf: string[];
  servicePrincipalName?: string[];
  userAccountControl?: number;
  delegateTo?: string[];
  rbcdFrom?: string[];
}

/**
 * Internal graph edge
 */
interface InternalEdge {
  source: string; // Node ID
  target: string; // Node ID
  relation: AttackRelationType;
  accessMask?: number;
  objectType?: string;
  isAbusable: boolean;
}

/**
 * BFS path result
 */
interface BFSPath {
  nodes: string[]; // Node IDs in order
  edges: InternalEdge[]; // Edges between nodes
}

/**
 * Attack Graph Service
 */
export class AttackGraphService {
  private nodes: Map<string, InternalNode> = new Map();
  private edges: Map<string, InternalEdge[]> = new Map(); // source -> edges
  private reverseEdges: Map<string, InternalEdge[]> = new Map(); // target -> edges
  private privilegedTargets: Map<string, AttackTarget> = new Map();
  private dnToId: Map<string, string> = new Map(); // DN -> node ID
  private domainSid: string = '';
  private domainName: string = '';

  /**
   * Initialize the attack graph service with AD data
   */
  constructor(
    private users: ADUser[],
    private groups: ADGroup[],
    private computers: ADComputer[],
    private aclEntries: AclEntry[],
    _certTemplates: ADCSCertificateTemplate[] = [],
    _gpos: ADGPO[] = [],
    domain?: { name?: string; sid?: string }
  ) {
    this.domainName = domain?.name || '';
    this.domainSid = domain?.sid || this.extractDomainSid();
    logger.debug(`AttackGraphService initialized with domain SID: ${this.domainSid}`);
  }

  /**
   * Build and export the attack graph
   */
  public export(maxPaths: number = 500): AttackGraphExport {
    const startTime = Date.now();

    // Build the graph
    this.buildGraph();

    // Identify privileged targets
    this.identifyPrivilegedTargets();

    // Find all attack paths
    const paths = this.findAllAttackPaths(maxPaths);

    // Compute statistics
    const stats = this.computeStats(paths);

    // Get unique nodes involved in paths
    const uniqueNodes = this.getUniqueNodes(paths);

    const duration = Date.now() - startTime;
    logger.info(
      `Attack graph exported: ${paths.length} paths, ${uniqueNodes.length} unique nodes in ${duration}ms`
    );

    return {
      version: '1.0',
      generatedAt: new Date().toISOString(),
      domain: this.domainName,
      targets: Array.from(this.privilegedTargets.values()),
      paths,
      stats,
      uniqueNodes,
    };
  }

  /**
   * Build the internal graph from AD data
   */
  private buildGraph(): void {
    // Add all nodes
    this.addUserNodes();
    this.addGroupNodes();
    this.addComputerNodes();

    // Add all edges
    this.addMembershipEdges();
    this.addAclEdges();
    this.addDelegationEdges();
    this.addKerberosEdges();

    logger.debug(
      `Graph built: ${this.nodes.size} nodes, ${this.countEdges()} edges`
    );
  }

  /**
   * Add user nodes to the graph
   */
  private addUserNodes(): void {
    for (const user of this.users) {
      const sid = this.extractSid(user);
      const id = sid || this.dnToId.get(user.dn.toLowerCase()) || this.generateId(user.dn);

      const node: InternalNode = {
        id,
        dn: user.dn,
        name: user.sAMAccountName || user.displayName || user.dn,
        type: 'user',
        sid,
        isEnabled: user.enabled,
        isPrivileged: user.adminCount === 1,
        adminCount: user.adminCount,
        memberOf: user.memberOf || [],
        servicePrincipalName: this.getSpn(user),
        userAccountControl: user.userAccountControl,
        delegateTo: this.getDelegationTargets(user),
      };

      this.nodes.set(id, node);
      this.dnToId.set(user.dn.toLowerCase(), id);
      this.edges.set(id, []);
      this.reverseEdges.set(id, []);
    }
  }

  /**
   * Add group nodes to the graph
   */
  private addGroupNodes(): void {
    for (const group of this.groups) {
      const sid = this.extractSid(group);
      const id = sid || this.generateId(group.dn);

      // Check if this is a privileged group by SID
      const isPrivileged = this.isPrivilegedBySid(sid);

      const node: InternalNode = {
        id,
        dn: group.dn,
        name: group.sAMAccountName || group.displayName || group.cn || group.dn,
        type: 'group',
        sid,
        isEnabled: true,
        isPrivileged,
        memberOf: group.memberOf || [],
      };

      this.nodes.set(id, node);
      this.dnToId.set(group.dn.toLowerCase(), id);
      this.edges.set(id, []);
      this.reverseEdges.set(id, []);
    }
  }

  /**
   * Add computer nodes to the graph
   */
  private addComputerNodes(): void {
    for (const computer of this.computers) {
      const sid = this.extractSid(computer);
      const id = sid || this.generateId(computer.dn);

      // Check if Domain Controller
      const memberOf = (computer as any).memberOf || [];
      const isDC = memberOf.some(
        (m: string) =>
          m.toLowerCase().includes('cn=domain controllers') ||
          m.toLowerCase().includes('cn=contrôleurs de domaine')
      );

      const node: InternalNode = {
        id,
        dn: computer.dn,
        name: computer.sAMAccountName || computer.dNSHostName || computer.cn || computer.dn,
        type: 'computer',
        sid,
        isEnabled: computer.enabled,
        isPrivileged: isDC,
        memberOf: memberOf,
        delegateTo: this.getDelegationTargets(computer),
        rbcdFrom: this.getRbcdPrincipals(computer),
      };

      this.nodes.set(id, node);
      this.dnToId.set(computer.dn.toLowerCase(), id);
      this.edges.set(id, []);
      this.reverseEdges.set(id, []);
    }
  }

  /**
   * Add membership edges (MemberOf)
   */
  private addMembershipEdges(): void {
    for (const [nodeId, node] of this.nodes) {
      for (const groupDn of node.memberOf) {
        const targetId = this.dnToId.get(groupDn.toLowerCase());
        if (targetId) {
          this.addEdge({
            source: nodeId,
            target: targetId,
            relation: 'MemberOf',
            isAbusable: false, // Membership itself isn't abusable, but paths through it are
          });
        }
      }
    }
  }

  /**
   * Add ACL-based edges
   */
  private addAclEdges(): void {
    for (const acl of this.aclEntries) {
      // Skip denied ACEs
      if (acl.aceType !== '0' && acl.aceType !== 'ACCESS_ALLOWED_ACE_TYPE') {
        continue;
      }

      const sourceId = this.resolveAclTrustee(acl.trustee);
      const targetId = this.dnToId.get(acl.objectDn.toLowerCase());

      if (!sourceId || !targetId) continue;

      // Determine relation type based on access mask and object type
      const relations = this.classifyAclRelation(acl);

      for (const relation of relations) {
        this.addEdge({
          source: sourceId,
          target: targetId,
          relation: relation.type,
          accessMask: acl.accessMask,
          objectType: acl.objectType,
          isAbusable: relation.isAbusable,
        });
      }
    }
  }

  /**
   * Add delegation edges
   */
  private addDelegationEdges(): void {
    for (const [nodeId, node] of this.nodes) {
      // Constrained delegation
      if (node.delegateTo && node.delegateTo.length > 0) {
        for (const spn of node.delegateTo) {
          // Try to resolve SPN to a target
          const targetId = this.resolveSPNTarget(spn);
          if (targetId) {
            this.addEdge({
              source: nodeId,
              target: targetId,
              relation: 'AllowedToDelegate',
              isAbusable: true,
            });
          }
        }
      }

      // RBCD - reverse direction: those who can act get edge TO this computer
      if (node.rbcdFrom && node.rbcdFrom.length > 0) {
        for (const principalSid of node.rbcdFrom) {
          const sourceId = this.nodes.has(principalSid)
            ? principalSid
            : this.findNodeBySid(principalSid);
          if (sourceId) {
            this.addEdge({
              source: sourceId,
              target: nodeId,
              relation: 'AllowedToAct',
              isAbusable: true,
            });
          }
        }
      }
    }
  }

  /**
   * Add Kerberos-related edges (HasSPN, NoPreauth)
   * Note: These are tracked as node properties for path classification
   */
  private addKerberosEdges(): void {
    // HasSPN and NoPreauth are tracked as node properties, not edges
    // They are used during path classification to determine path type
    // (KERBEROASTING, ASREP_ROASTING)
  }

  /**
   * Identify privileged targets
   */
  private identifyPrivilegedTargets(): void {
    for (const [nodeId, node] of this.nodes) {
      let reason: string | null = null;

      // Check SID-based privileged groups
      if (node.sid) {
        if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.DOMAIN_ADMINS)) {
          reason = 'Domain Admins';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.ENTERPRISE_ADMINS)) {
          reason = 'Enterprise Admins';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.SCHEMA_ADMINS)) {
          reason = 'Schema Admins';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.ADMINISTRATORS)) {
          reason = 'Administrators';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.DOMAIN_CONTROLLERS)) {
          reason = 'Domain Controllers';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.ACCOUNT_OPERATORS)) {
          reason = 'Account Operators';
        } else if (node.sid.endsWith(PRIVILEGED_SID_SUFFIXES.BACKUP_OPERATORS)) {
          reason = 'Backup Operators';
        }
      }

      // Check adminCount=1
      if (!reason && node.adminCount === 1) {
        reason = 'adminCount=1';
      }

      // Check name-based privileged groups
      if (!reason && node.type === 'group') {
        const nameLower = node.name.toLowerCase();
        if (
          nameLower === 'domain admins' ||
          nameLower === 'admins du domaine' ||
          nameLower === 'administrateurs du domaine'
        ) {
          reason = 'Domain Admins';
        } else if (
          nameLower === 'enterprise admins' ||
          nameLower === 'administrateurs de l\'entreprise'
        ) {
          reason = 'Enterprise Admins';
        } else if (nameLower === 'administrators' || nameLower === 'administrateurs') {
          reason = 'Administrators';
        }
      }

      // Check Domain Controller computers
      if (!reason && node.type === 'computer' && node.isPrivileged) {
        reason = 'Domain Controller';
      }

      if (reason) {
        node.isPrivileged = true;
        this.privilegedTargets.set(nodeId, {
          id: nodeId,
          name: node.name,
          type: node.type,
          sid: node.sid,
          dn: node.dn,
          reason,
        });
      }
    }

    logger.debug(`Identified ${this.privilegedTargets.size} privileged targets`);
  }

  /**
   * Find all attack paths using BFS
   */
  private findAllAttackPaths(maxPaths: number): AttackPath[] {
    const paths: AttackPath[] = [];
    const targetIds = Array.from(this.privilegedTargets.keys());

    // For each non-privileged node, find shortest path to any privileged target
    for (const [sourceId, sourceNode] of this.nodes) {
      // Skip if source is already privileged
      if (sourceNode.isPrivileged) continue;

      // Skip disabled users
      if (sourceNode.type === 'user' && !sourceNode.isEnabled) continue;

      // BFS to find shortest path to any target
      const path = this.bfsShortestPath(sourceId, targetIds);

      if (path && path.nodes.length > 1) {
        const attackPath = this.buildAttackPath(path, sourceNode, paths.length + 1);
        if (attackPath) {
          paths.push(attackPath);

          if (paths.length >= maxPaths) {
            logger.debug(`Reached max paths limit: ${maxPaths}`);
            break;
          }
        }
      }
    }

    // Sort by risk (critical first) then by hops (shortest first)
    paths.sort((a, b) => {
      const riskOrder: Record<AttackPathRisk, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
      };
      if (riskOrder[a.risk] !== riskOrder[b.risk]) {
        return riskOrder[a.risk] - riskOrder[b.risk];
      }
      return a.hops - b.hops;
    });

    return paths;
  }

  /**
   * BFS to find shortest path from source to any target
   */
  private bfsShortestPath(sourceId: string, targetIds: string[]): BFSPath | null {
    const targetSet = new Set(targetIds);
    const visited = new Set<string>([sourceId]);
    const queue: { nodeId: string; path: BFSPath }[] = [
      { nodeId: sourceId, path: { nodes: [sourceId], edges: [] } },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;

      // Check if we reached a target
      if (targetSet.has(current.nodeId) && current.path.nodes.length > 1) {
        return current.path;
      }

      // Early termination for very long paths
      if (current.path.nodes.length > 6) continue;

      // Explore neighbors
      const outEdges = this.edges.get(current.nodeId) || [];
      for (const edge of outEdges) {
        if (visited.has(edge.target)) continue;
        visited.add(edge.target);

        const newPath: BFSPath = {
          nodes: [...current.path.nodes, edge.target],
          edges: [...current.path.edges, edge],
        };

        // Prioritize paths to targets
        if (targetSet.has(edge.target)) {
          return newPath;
        }

        queue.push({ nodeId: edge.target, path: newPath });
      }
    }

    return null;
  }

  /**
   * Build an AttackPath from BFS result
   */
  private buildAttackPath(
    bfsPath: BFSPath,
    sourceNode: InternalNode,
    pathIndex: number
  ): AttackPath | null {
    const chain: AttackChainElement[] = [];

    // Build alternating node-relation-node chain
    for (let i = 0; i < bfsPath.nodes.length; i++) {
      const nodeId = bfsPath.nodes[i];
      if (!nodeId) continue;
      const node = this.nodes.get(nodeId);
      if (!node) continue;

      // Add node
      chain.push(this.toAttackGraphNode(node));

      // Add relation (if not last node)
      if (i < bfsPath.edges.length) {
        const edge = bfsPath.edges[i];
        if (edge) {
          chain.push(this.toAttackGraphRelation(edge));
        }
      }
    }

    // Get target node
    const targetId = bfsPath.nodes[bfsPath.nodes.length - 1];
    if (!targetId) return null;
    const targetNode = this.nodes.get(targetId);
    if (!targetNode) return null;

    // Classify path type
    const pathType = this.classifyPathType(bfsPath);

    // Calculate risk
    const risk = this.calculatePathRisk(bfsPath, pathType);

    // Generate description and mitigation
    const description = this.generateDescription(bfsPath, pathType, sourceNode, targetNode);
    const mitigation = this.generateMitigation(bfsPath, pathType);

    return {
      id: `path-${String(pathIndex).padStart(3, '0')}`,
      risk,
      type: pathType,
      hops: bfsPath.edges.length,
      description,
      chain,
      entryPoint: this.toEntryPoint(sourceNode),
      target: this.toAttackGraphNode(targetNode),
      mitigation,
    };
  }

  /**
   * Classify path type based on edges
   */
  private classifyPathType(path: BFSPath): AttackPathType {
    const relations = path.edges.map((e) => e.relation);

    // Check for DCSync
    if (relations.includes('DCSync')) {
      return 'DCSYNC';
    }

    // Check for delegation abuse
    if (relations.includes('AllowedToDelegate') || relations.includes('AllowedToAct')) {
      return 'DELEGATION_ABUSE';
    }

    // Check for Kerberoasting (user with SPN -> privileged)
    const firstNodeId = path.nodes[0];
    const sourceNode = firstNodeId ? this.nodes.get(firstNodeId) : undefined;
    if (
      sourceNode?.type === 'user' &&
      sourceNode.servicePrincipalName &&
      sourceNode.servicePrincipalName.length > 0
    ) {
      return 'KERBEROASTING';
    }

    // Check for AS-REP roasting
    if (
      sourceNode?.userAccountControl &&
      (sourceNode.userAccountControl & 0x400000) !== 0
    ) {
      return 'ASREP_ROASTING';
    }

    // Check for ownership abuse
    if (relations.includes('Owns')) {
      return 'OWNERSHIP_ABUSE';
    }

    // Check for ACL abuse
    const aclRelations: AttackRelationType[] = [
      'GenericAll',
      'WriteDacl',
      'WriteOwner',
      'GenericWrite',
      'ForceChangePassword',
      'AddMember',
    ];
    if (relations.some((r) => aclRelations.includes(r))) {
      return 'ACL_ABUSE';
    }

    // Check for pure group membership
    if (relations.every((r) => r === 'MemberOf')) {
      return 'GROUP_MEMBERSHIP';
    }

    // Default to ACL abuse
    return 'ACL_ABUSE';
  }

  /**
   * Calculate risk level for a path
   */
  private calculatePathRisk(path: BFSPath, pathType: AttackPathType): AttackPathRisk {
    const hops = path.edges.length;
    const hasAbusableEdge = path.edges.some((e) => e.isAbusable);

    // DCSync is always critical
    if (pathType === 'DCSYNC') return 'critical';

    // Short paths with abusable edges are critical
    if (hops <= 2 && hasAbusableEdge) return 'critical';

    // Delegation abuse is high risk
    if (pathType === 'DELEGATION_ABUSE') return 'high';

    // Short paths are high risk
    if (hops <= 2) return 'high';

    // Medium paths
    if (hops <= 4) return 'medium';

    // Long paths are lower risk
    return 'low';
  }

  /**
   * Generate path description
   */
  private generateDescription(
    path: BFSPath,
    pathType: AttackPathType,
    source: InternalNode,
    target: InternalNode
  ): string {
    const typeDescriptions: Record<AttackPathType, string> = {
      ACL_ABUSE: 'can abuse ACL permissions to reach',
      KERBEROASTING: 'has an SPN and can be Kerberoasted to reach',
      ASREP_ROASTING: 'has no pre-authentication and can be AS-REP roasted to reach',
      DELEGATION_ABUSE: 'can abuse delegation to reach',
      LATERAL_MOVEMENT: 'can move laterally to reach',
      CERTIFICATE_ABUSE: 'can abuse certificate services to reach',
      GROUP_MEMBERSHIP: 'is a member of groups leading to',
      DCSYNC: 'has DCSync rights to',
      OWNERSHIP_ABUSE: 'owns objects leading to',
    };

    return `${source.name} ${typeDescriptions[pathType]} ${target.name} in ${path.edges.length} hop(s)`;
  }

  /**
   * Generate mitigation advice
   */
  private generateMitigation(_path: BFSPath, pathType: AttackPathType): string {
    const mitigations: Record<AttackPathType, string> = {
      ACL_ABUSE:
        'Review and remove unnecessary ACL permissions. Apply least privilege principle.',
      KERBEROASTING:
        'Remove unnecessary SPNs from user accounts. Use Group Managed Service Accounts (gMSA) or strong passwords for service accounts.',
      ASREP_ROASTING:
        'Enable Kerberos pre-authentication for all user accounts.',
      DELEGATION_ABUSE:
        'Review and restrict delegation settings. Use resource-based constrained delegation with explicit trusts.',
      LATERAL_MOVEMENT:
        'Segment networks and restrict local admin access. Implement LAPS for local administrator passwords.',
      CERTIFICATE_ABUSE:
        'Review certificate template permissions. Disable vulnerable enrollment patterns.',
      GROUP_MEMBERSHIP:
        'Review nested group memberships. Remove unnecessary members from privileged groups.',
      DCSYNC:
        'Remove DCSync rights from non-DC accounts. Monitor for DCSync activity.',
      OWNERSHIP_ABUSE:
        'Review object ownership. Ensure privileged objects are owned by appropriate administrators.',
    };

    return mitigations[pathType];
  }

  /**
   * Convert internal node to export format
   */
  private toAttackGraphNode(node: InternalNode): AttackGraphNode {
    return {
      id: node.id,
      name: node.name,
      type: node.type,
      sid: node.sid,
      dn: node.dn,
      domain: this.domainName,
      isEnabled: node.isEnabled,
      isPrivileged: node.isPrivileged,
    };
  }

  /**
   * Convert internal edge to export relation
   */
  private toAttackGraphRelation(edge: InternalEdge): AttackGraphRelation {
    return {
      relation: edge.relation,
      isAbusable: edge.isAbusable,
      accessMask: edge.accessMask,
      objectType: edge.objectType,
    };
  }

  /**
   * Convert node to entry point
   */
  private toEntryPoint(node: InternalNode): AttackEntryPoint {
    return {
      id: node.id,
      name: node.name,
      type: node.type,
      properties: {
        hasSPN: node.servicePrincipalName && node.servicePrincipalName.length > 0,
        noPreauth: node.userAccountControl
          ? (node.userAccountControl & 0x400000) !== 0
          : false,
        passwordNotExpire: node.userAccountControl
          ? (node.userAccountControl & 0x10000) !== 0
          : false,
        unconstrained: node.userAccountControl
          ? (node.userAccountControl & 0x80000) !== 0
          : false,
        constrained: node.delegateTo && node.delegateTo.length > 0,
        rbcd: node.rbcdFrom && node.rbcdFrom.length > 0,
        adminCount: node.adminCount === 1,
        enabled: node.isEnabled,
      },
    };
  }

  /**
   * Compute statistics
   */
  private computeStats(paths: AttackPath[]): AttackGraphStats {
    const byRisk = { critical: 0, high: 0, medium: 0, low: 0 };
    const byType: Record<AttackPathType, number> = {
      ACL_ABUSE: 0,
      KERBEROASTING: 0,
      ASREP_ROASTING: 0,
      DELEGATION_ABUSE: 0,
      LATERAL_MOVEMENT: 0,
      CERTIFICATE_ABUSE: 0,
      GROUP_MEMBERSHIP: 0,
      DCSYNC: 0,
      OWNERSHIP_ABUSE: 0,
    };

    let totalHops = 0;
    let shortestPath = Infinity;
    let longestPath = 0;

    for (const path of paths) {
      byRisk[path.risk]++;
      byType[path.type]++;
      totalHops += path.hops;
      shortestPath = Math.min(shortestPath, path.hops);
      longestPath = Math.max(longestPath, path.hops);
    }

    return {
      totalPaths: paths.length,
      byRisk,
      byType,
      averageHops: paths.length > 0 ? Math.round((totalHops / paths.length) * 100) / 100 : 0,
      shortestPath: paths.length > 0 ? shortestPath : 0,
      longestPath: paths.length > 0 ? longestPath : 0,
    };
  }

  /**
   * Get unique nodes involved in paths
   */
  private getUniqueNodes(paths: AttackPath[]): AttackGraphUniqueNode[] {
    const nodeCount = new Map<string, { node: AttackGraphNode; count: number }>();

    for (const path of paths) {
      for (const element of path.chain) {
        if (isAttackGraphNode(element)) {
          const existing = nodeCount.get(element.id);
          if (existing) {
            existing.count++;
          } else {
            nodeCount.set(element.id, { node: element, count: 1 });
          }
        }
      }
    }

    return Array.from(nodeCount.values())
      .map(({ node, count }) => ({
        id: node.id,
        name: node.name,
        type: node.type,
        pathCount: count,
        sid: node.sid,
      }))
      .sort((a, b) => b.pathCount - a.pathCount);
  }

  // ========== Helper Methods ==========

  /**
   * Add an edge to the graph
   */
  private addEdge(edge: InternalEdge): void {
    const sourceEdges = this.edges.get(edge.source);
    if (sourceEdges) {
      sourceEdges.push(edge);
    }

    const targetEdges = this.reverseEdges.get(edge.target);
    if (targetEdges) {
      targetEdges.push(edge);
    }
  }

  /**
   * Count total edges
   */
  private countEdges(): number {
    let count = 0;
    for (const edges of this.edges.values()) {
      count += edges.length;
    }
    return count;
  }

  /**
   * Extract SID from AD object
   */
  private extractSid(obj: ADUser | ADGroup | ADComputer): string | undefined {
    const sid = (obj as any).objectSid || (obj as any).objectSID || (obj as any).sid;
    if (typeof sid === 'string') return sid;
    if (Buffer.isBuffer(sid)) return this.bufferToSid(sid);
    return undefined;
  }

  /**
   * Convert Buffer to SID string
   */
  private bufferToSid(buffer: Buffer): string {
    if (buffer.length < 8) return '';

    const revision = buffer.readUInt8(0);
    const subAuthCount = buffer.readUInt8(1);
    const authority =
      buffer.readUInt8(2) * Math.pow(2, 40) +
      buffer.readUInt8(3) * Math.pow(2, 32) +
      buffer.readUInt8(4) * Math.pow(2, 24) +
      buffer.readUInt8(5) * Math.pow(2, 16) +
      buffer.readUInt8(6) * Math.pow(2, 8) +
      buffer.readUInt8(7);

    let sid = `S-${revision}-${authority}`;

    for (let i = 0; i < subAuthCount; i++) {
      const offset = 8 + i * 4;
      if (offset + 4 <= buffer.length) {
        const subAuth = buffer.readUInt32LE(offset);
        sid += `-${subAuth}`;
      }
    }

    return sid;
  }

  /**
   * Extract domain SID from first user/computer SID
   */
  private extractDomainSid(): string {
    for (const user of this.users) {
      const sid = this.extractSid(user);
      if (sid) {
        // Domain SID is everything except the last RID
        const parts = sid.split('-');
        if (parts.length > 4) {
          return parts.slice(0, -1).join('-');
        }
      }
    }
    return '';
  }

  /**
   * Check if SID is privileged
   */
  private isPrivilegedBySid(sid?: string): boolean {
    if (!sid) return false;

    for (const suffix of Object.values(PRIVILEGED_SID_SUFFIXES)) {
      if (sid.endsWith(suffix)) return true;
    }

    return false;
  }

  /**
   * Generate ID from DN
   */
  private generateId(dn: string): string {
    return `dn:${dn.toLowerCase()}`;
  }

  /**
   * Get SPN array from user
   */
  private getSpn(user: ADUser): string[] | undefined {
    const spn = (user as any).servicePrincipalName;
    if (!spn) return undefined;
    return Array.isArray(spn) ? spn : [spn];
  }

  /**
   * Get delegation targets
   */
  private getDelegationTargets(obj: ADUser | ADComputer): string[] | undefined {
    const attr = (obj as any)['msDS-AllowedToDelegateTo'];
    if (!attr) return undefined;
    return Array.isArray(attr) ? attr : [attr];
  }

  /**
   * Get RBCD principals
   */
  private getRbcdPrincipals(computer: ADComputer): string[] | undefined {
    const attr = (computer as any)['msDS-AllowedToActOnBehalfOfOtherIdentity'];
    if (!attr) return undefined;

    // This is typically a binary security descriptor - would need to parse it
    // For now, just track that RBCD is configured
    return [];
  }

  /**
   * Resolve ACL trustee to node ID
   */
  private resolveAclTrustee(trustee: string): string | undefined {
    // Trustee might be a SID or DN
    if (trustee.startsWith('S-1-')) {
      // It's a SID - look up by SID
      if (this.nodes.has(trustee)) {
        return trustee;
      }
      return this.findNodeBySid(trustee);
    }

    // It's a DN
    return this.dnToId.get(trustee.toLowerCase());
  }

  /**
   * Find node by SID
   */
  private findNodeBySid(sid: string): string | undefined {
    for (const [nodeId, node] of this.nodes) {
      if (node.sid === sid) return nodeId;
    }
    return undefined;
  }

  /**
   * Resolve SPN to target node
   */
  private resolveSPNTarget(spn: string): string | undefined {
    // SPN format: service/host:port or service/host
    const parts = spn.split('/');
    if (parts.length < 2 || !parts[1]) return undefined;

    const hostPart = parts[1].split(':')[0];
    if (!hostPart) return undefined;
    const host = hostPart.toLowerCase();

    // Look for computer with matching hostname
    const hostShort = host.split('.')[0] || host;
    for (const [nodeId, node] of this.nodes) {
      if (node.type === 'computer') {
        const nodeName = node.name.toLowerCase().replace(/\$$/, '');
        if (nodeName === host || nodeName.startsWith(hostShort)) {
          return nodeId;
        }
      }
    }

    return undefined;
  }

  /**
   * Classify ACL to relation types
   */
  private classifyAclRelation(
    acl: AclEntry
  ): { type: AttackRelationType; isAbusable: boolean }[] {
    const relations: { type: AttackRelationType; isAbusable: boolean }[] = [];
    const mask = acl.accessMask;
    const objectType = acl.objectType?.toLowerCase();

    // GenericAll
    if (mask & ACCESS_MASK.GENERIC_ALL) {
      relations.push({ type: 'GenericAll', isAbusable: true });
    }

    // GenericWrite
    if (mask & ACCESS_MASK.GENERIC_WRITE) {
      relations.push({ type: 'GenericWrite', isAbusable: true });
    }

    // WriteDacl
    if (mask & ACCESS_MASK.WRITE_DACL) {
      relations.push({ type: 'WriteDacl', isAbusable: true });
    }

    // WriteOwner
    if (mask & ACCESS_MASK.WRITE_OWNER) {
      relations.push({ type: 'WriteOwner', isAbusable: true });
    }

    // Extended rights - check object type
    if (mask & ACCESS_MASK.CONTROL_ACCESS && objectType) {
      // ForceChangePassword
      if (objectType === ACL_GUIDS.FORCE_CHANGE_PASSWORD.toLowerCase()) {
        relations.push({ type: 'ForceChangePassword', isAbusable: true });
      }

      // DCSync rights
      if (
        objectType === ACL_GUIDS.DS_REPLICATION_GET_CHANGES.toLowerCase() ||
        objectType === ACL_GUIDS.DS_REPLICATION_GET_CHANGES_ALL.toLowerCase()
      ) {
        relations.push({ type: 'DCSync', isAbusable: true });
      }
    }

    // Self membership (AddMember)
    if (mask & ACCESS_MASK.SELF && objectType === ACL_GUIDS.SELF_MEMBERSHIP.toLowerCase()) {
      relations.push({ type: 'AddMember', isAbusable: true });
    }

    return relations;
  }
}

/**
 * Create and export attack graph
 */
export function computeAttackGraph(
  users: ADUser[],
  groups: ADGroup[],
  computers: ADComputer[],
  aclEntries: AclEntry[],
  certTemplates: ADCSCertificateTemplate[] = [],
  gpos: ADGPO[] = [],
  domain?: { name?: string; sid?: string },
  maxPaths: number = 500
): AttackGraphExport {
  const service = new AttackGraphService(
    users,
    groups,
    computers,
    aclEntries,
    certTemplates,
    gpos,
    domain
  );

  return service.export(maxPaths);
}
